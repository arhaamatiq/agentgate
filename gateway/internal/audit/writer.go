package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
)

// ErrHeadMoved means the chain head in the database is not the one this
// writer committed. The writer refuses to continue the chain.
var ErrHeadMoved = errors.New("audit chain head moved unexpectedly (possible tampering)")

type WriterConfig struct {
	Brokers         []string
	Topic           string
	CheckpointTopic string
	Group           string
	DSN             string
	SigningKey      ed25519.PrivateKey // nil: unsigned checkpoints
	CheckpointEvery int                // rows
	CheckpointAfter time.Duration
}

type head struct {
	seq        int64
	hash       []byte
	offset     int64
	lastCkSeq  int64
	lastCkTime time.Time
}

// Writer consumes decisions and appends them to the hash chain. The Kafka
// offset is stored in the same transaction as the rows; on (re)assignment
// the writer resumes from the database, never from Kafka's committed offset.
type Writer struct {
	cfg   WriterConfig
	pool  *pgxpool.Pool
	cl    *kgo.Client
	mu    sync.Mutex
	heads map[int32]*head

	Written    func(n int)
	Duplicates func(n int)
}

func NewWriter(ctx context.Context, cfg WriterConfig) (*Writer, error) {
	if cfg.CheckpointEvery <= 0 {
		cfg.CheckpointEvery = 1000
	}
	if cfg.CheckpointAfter <= 0 {
		cfg.CheckpointAfter = 5 * time.Second
	}
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return nil, err
	}
	w := &Writer{cfg: cfg, pool: pool, heads: map[int32]*head{}}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ConsumerGroup(cfg.Group),
		kgo.ConsumeTopics(cfg.Topic),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
		kgo.AdjustFetchOffsetsFn(w.resumeFromDatabase),
		kgo.OnPartitionsRevoked(w.dropHeads),
		kgo.OnPartitionsLost(w.dropHeads),
		kgo.DefaultProduceTopic(cfg.CheckpointTopic),
		kgo.RequiredAcks(kgo.AllISRAcks()),
	)
	if err != nil {
		pool.Close()
		return nil, err
	}
	w.cl = cl
	compact := "compact"
	_ = EnsureTopic(ctx, cl, cfg.CheckpointTopic, 1, map[string]*string{"cleanup.policy": &compact})
	return w, nil
}

func (w *Writer) loadHead(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, chain int32) (*head, error) {
	h := &head{seq: 0, hash: GenesisHash, offset: -1}
	err := q.QueryRow(ctx,
		`SELECT seq, hash, kafka_offset FROM audit_events WHERE chain_id = $1 ORDER BY seq DESC LIMIT 1`, chain,
	).Scan(&h.seq, &h.hash, &h.offset)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, nil
	}
	return h, err
}

func (w *Writer) resumeFromDatabase(ctx context.Context, offsets map[string]map[int32]kgo.Offset) (map[string]map[int32]kgo.Offset, error) {
	for topic, parts := range offsets {
		for p := range parts {
			h, err := w.loadHead(ctx, w.pool, p)
			if err != nil {
				return nil, err
			}
			h.lastCkSeq, h.lastCkTime = h.seq, time.Now()
			w.mu.Lock()
			w.heads[p] = h
			w.mu.Unlock()
			if h.offset >= 0 {
				parts[p] = kgo.NewOffset().At(h.offset + 1)
			} else {
				parts[p] = kgo.NewOffset().AtStart()
			}
			slog.Info("resuming chain from database", "topic", topic, "chain", p, "seq", h.seq, "next_offset", h.offset+1)
		}
	}
	return offsets, nil
}

func (w *Writer) dropHeads(ctx context.Context, _ *kgo.Client, lost map[string][]int32) {
	w.checkpointAll(ctx, true)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, parts := range lost {
		for _, p := range parts {
			delete(w.heads, p)
		}
	}
}

// Run consumes until ctx is cancelled.
func (w *Writer) Run(ctx context.Context) error {
	for {
		fetches := w.cl.PollRecords(ctx, 5000)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			return ctx.Err()
		}
		fetches.EachError(func(t string, p int32, err error) {
			slog.Error("fetch error", "topic", t, "partition", p, "err", err)
		})
		byChain := map[int32][]*kgo.Record{}
		var all []*kgo.Record
		fetches.EachRecord(func(r *kgo.Record) {
			byChain[r.Partition] = append(byChain[r.Partition], r)
			all = append(all, r)
		})
		for chain, recs := range byChain {
			for attempt := 0; ; attempt++ {
				err := w.writeBatch(ctx, chain, recs)
				if err == nil {
					break
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if errors.Is(err, ErrHeadMoved) {
					return err
				}
				backoff := time.Duration(min(attempt+1, 20)) * 250 * time.Millisecond
				slog.Error("audit batch write failed; retrying", "chain", chain, "records", len(recs), "err", err, "backoff", backoff)
				time.Sleep(backoff)
			}
		}
		if len(all) > 0 {
			// Advisory only: the database offset is the source of truth.
			_ = w.cl.CommitRecords(ctx, all...)
		}
		w.checkpointAll(ctx, false)
		w.cl.AllowRebalance()
	}
}

type row struct {
	offset    int64
	eventID   uuid.UUID
	ts        time.Time
	agent     string
	session   string
	tool      string
	verdict   string
	tier      int16
	policy    string
	failed    bool
	eventText string
}

// parseRecord validates a record. Anything that is not a well-formed
// decision event is wrapped in a deterministic "invalid_record" envelope and
// still chained: the log never silently drops input.
func parseRecord(r *kgo.Record) row {
	var ev Event
	ok := utf8.Valid(r.Value) && json.Unmarshal(r.Value, &ev) == nil
	id, idErr := uuid.Parse(ev.EventID)
	ts, tsErr := time.Parse(time.RFC3339Nano, ev.TS)
	if ok && idErr == nil && tsErr == nil && ev.Verdict != "" {
		return row{
			offset: r.Offset, eventID: id, ts: ts, agent: ev.AgentID, session: ev.SessionID,
			tool: ev.ToolName, verdict: ev.Verdict, tier: int16(ev.Tier), policy: ev.Policy,
			failed: ev.FailClosed, eventText: string(r.Value),
		}
	}
	id = uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("kafka://%s/%d/%d", r.Topic, r.Partition, r.Offset)))
	env, _ := json.Marshal(map[string]any{
		"v": 1, "type": "invalid_record", "event_id": id.String(),
		"ts": r.Timestamp.UTC().Format(time.RFC3339Nano), "raw_b64": base64.StdEncoding.EncodeToString(r.Value),
	})
	return row{
		offset: r.Offset, eventID: id, ts: r.Timestamp, agent: "", session: "", tool: "",
		verdict: "invalid_record", tier: 0, policy: "", eventText: string(env),
	}
}

func (w *Writer) writeBatch(ctx context.Context, chain int32, recs []*kgo.Record) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(918273, $1)`, chain); err != nil {
		return err
	}
	h, err := w.loadHead(ctx, tx, chain)
	if err != nil {
		return err
	}
	// The database head must be exactly what this writer last committed. If
	// it moved, someone else wrote to the chain (a forged row, or a zombie
	// writer after a rebalance): stop rather than chain onto it.
	w.mu.Lock()
	known := w.heads[chain]
	w.mu.Unlock()
	if known != nil && known.seq > 0 && (known.seq != h.seq || !bytes.Equal(known.hash, h.hash)) {
		return fmt.Errorf("%w: chain %d head is seq %d, writer expected seq %d", ErrHeadMoved, chain, h.seq, known.seq)
	}

	rows := make([]row, 0, len(recs))
	ids := make([]uuid.UUID, 0, len(recs))
	seen := map[uuid.UUID]bool{}
	for _, r := range recs {
		if r.Offset <= h.offset {
			continue // already written (redelivery after a crash or rebalance)
		}
		rw := parseRecord(r)
		if seen[rw.eventID] {
			continue
		}
		seen[rw.eventID] = true
		rows = append(rows, rw)
		ids = append(ids, rw.eventID)
	}
	if len(rows) == 0 {
		return tx.Commit(ctx)
	}
	// Producer retries are idempotent, but guard anyway: an event_id that is
	// already chained is skipped, not chained twice.
	dups := map[uuid.UUID]bool{}
	dupRows, err := tx.Query(ctx, `SELECT event_id FROM audit_events WHERE event_id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	for dupRows.Next() {
		var id uuid.UUID
		if err := dupRows.Scan(&id); err != nil {
			dupRows.Close()
			return err
		}
		dups[id] = true
	}
	dupRows.Close()

	seq, prev := h.seq, h.hash
	var lastOffset int64
	copyRows := make([][]any, 0, len(rows))
	for _, rw := range rows {
		if dups[rw.eventID] {
			continue
		}
		seq++
		hash := LinkHash(prev, chain, seq, []byte(rw.eventText))
		copyRows = append(copyRows, []any{
			chain, seq, rw.offset, rw.eventID, rw.ts, rw.agent, rw.session, rw.tool,
			rw.verdict, rw.tier, rw.policy, rw.failed, rw.eventText, prev, hash,
		})
		prev, lastOffset = hash, rw.offset
	}
	if len(copyRows) > 0 {
		_, err = tx.CopyFrom(ctx, pgx.Identifier{"audit_events"}, []string{
			"chain_id", "seq", "kafka_offset", "event_id", "ts", "agent_id", "session_id", "tool_name",
			"verdict", "tier", "policy", "fail_closed", "event", "prev_hash", "hash",
		}, pgx.CopyFromRows(copyRows))
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	w.mu.Lock()
	cur := w.heads[chain]
	if cur == nil {
		cur = &head{lastCkSeq: h.seq, lastCkTime: time.Now()}
		w.heads[chain] = cur
	}
	if len(copyRows) > 0 {
		cur.seq, cur.hash, cur.offset = seq, prev, lastOffset
	}
	w.mu.Unlock()
	if w.Written != nil {
		w.Written(len(copyRows))
	}
	if w.Duplicates != nil && len(dups) > 0 {
		w.Duplicates(len(dups))
	}
	return nil
}

func (w *Writer) checkpointAll(ctx context.Context, force bool) {
	w.mu.Lock()
	var due []Checkpoint
	now := time.Now()
	for chain, h := range w.heads {
		if h.seq == 0 || h.seq == h.lastCkSeq {
			continue
		}
		if force || h.seq-h.lastCkSeq >= int64(w.cfg.CheckpointEvery) || now.Sub(h.lastCkTime) >= w.cfg.CheckpointAfter {
			due = append(due, Checkpoint{ChainID: chain, Seq: h.seq, Hash: hexHash(h.hash),
				KafkaOffset: h.offset, TS: now.UTC().Format(time.RFC3339Nano)})
			h.lastCkSeq, h.lastCkTime = h.seq, now
		}
	}
	w.mu.Unlock()
	for i := range due {
		c := &due[i]
		if w.cfg.SigningKey != nil {
			c.Sign(w.cfg.SigningKey)
		}
		b, _ := json.Marshal(c)
		key := []byte(fmt.Sprintf("%d:%020d", c.ChainID, c.Seq))
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		err := w.cl.ProduceSync(pctx, &kgo.Record{Key: key, Value: b}).FirstErr()
		cancel()
		if err != nil {
			slog.Error("checkpoint publish failed", "chain", c.ChainID, "seq", c.Seq, "err", err)
		}
	}
}

// Close publishes final checkpoints, leaves the group and closes the pool.
func (w *Writer) Close(ctx context.Context) {
	w.checkpointAll(ctx, true)
	w.cl.Close()
	w.pool.Close()
}
