package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

type Problem struct {
	ChainID int32  `json:"chain_id"`
	Seq     int64  `json:"seq"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
}

type Report struct {
	OK                   bool      `json:"ok"`
	Chains               int       `json:"chains"`
	RowsVerified         int64     `json:"rows_verified"`
	RowsCrossChecked     int64     `json:"rows_cross_checked_with_kafka"`
	CheckpointsVerified  int       `json:"checkpoints_verified"`
	CheckpointsSigned    bool      `json:"checkpoints_signed"`
	Problems             []Problem `json:"problems"`
	ProblemsTruncated    bool      `json:"problems_truncated,omitempty"`
	DurationMS           int64     `json:"duration_ms"`
	CheckpointSourceNote string    `json:"checkpoint_source,omitempty"`
}

const maxProblems = 1000

func (r *Report) add(p Problem) {
	if len(r.Problems) >= maxProblems {
		r.ProblemsTruncated = true
		return
	}
	r.Problems = append(r.Problems, p)
}

type VerifyConfig struct {
	DSN             string
	Brokers         []string // optional: enables checkpoint verification
	CheckpointTopic string
	PublicKey       ed25519.PublicKey // optional: enables signature checks
	// CrossCheckTopic, if set, compares every row with the Kafka record it
	// claims to come from (byte-identical). Catches rows forged directly in
	// the database, as long as Kafka still retains the source records.
	CrossCheckTopic string
}

// Verify recomputes every link of every chain and checks every checkpoint.
//
//   - edited row:        stored hash != recomputed hash, or a column disagrees
//     with the hashed event
//   - deleted row:       gap in seq, and prev_hash of the next row mismatches
//   - truncated tail:    a checkpoint names a seq that no longer exists
//   - rewritten chain:   a checkpoint hash differs from the row's hash
func Verify(ctx context.Context, cfg VerifyConfig) (*Report, error) {
	start := time.Now()
	rep := &Report{}
	conn, err := pgx.Connect(ctx, cfg.DSN)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, `
		SELECT chain_id, seq, kafka_offset, event_id, agent_id, session_id, tool_name,
		       verdict, tier, policy, fail_closed, event, prev_hash, hash
		FROM audit_events ORDER BY chain_id, seq`)
	if err != nil {
		return nil, err
	}
	heads := map[int32][]byte{} // chain -> hash at seq, for checkpoint lookups
	hashes := map[int32]map[int64][]byte{}
	type src struct {
		chain  int32
		seq    int64
		offset int64
		digest [32]byte
	}
	var sources []src
	var (
		curChain   int32 = -1
		expectSeq  int64
		prevHash   []byte
		prevOffset int64
	)
	for rows.Next() {
		var (
			chain                                     int32
			seq, offset                               int64
			eventID                                   uuid.UUID
			agent, session, tool, verdict, policy, ev string
			tier                                      int16
			failed                                    bool
			prev, hash                                []byte
		)
		if err := rows.Scan(&chain, &seq, &offset, &eventID, &agent, &session, &tool, &verdict, &tier, &policy, &failed, &ev, &prev, &hash); err != nil {
			return nil, err
		}
		if chain != curChain {
			curChain, expectSeq, prevHash, prevOffset = chain, 1, GenesisHash, -1
			rep.Chains++
			hashes[chain] = map[int64][]byte{}
		}
		if seq != expectSeq {
			rep.add(Problem{chain, expectSeq, "missing_rows",
				fmt.Sprintf("seq %d..%d absent (rows deleted)", expectSeq, seq-1)})
		}
		if !bytes.Equal(prev, prevHash) {
			rep.add(Problem{chain, seq, "broken_link", "prev_hash does not match the previous row's hash"})
		}
		if want := LinkHash(prev, chain, seq, []byte(ev)); !bytes.Equal(want, hash) {
			rep.add(Problem{chain, seq, "hash_mismatch", "event content does not match its hash (row edited)"})
		}
		if offset <= prevOffset {
			rep.add(Problem{chain, seq, "offset_order", "kafka_offset not increasing"})
		}
		if d := columnDrift(ev, eventID, agent, session, tool, verdict, tier, policy, failed); d != "" {
			rep.add(Problem{chain, seq, "column_mismatch", d})
		}
		hashes[chain][seq] = hash
		heads[chain] = hash
		if cfg.CrossCheckTopic != "" {
			sources = append(sources, src{chain, seq, offset, sourceDigest(ev, verdict)})
		}
		rep.RowsVerified++
		expectSeq, prevHash, prevOffset = seq+1, hash, offset
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(cfg.Brokers) > 0 {
		cks, err := readCheckpoints(ctx, cfg.Brokers, cfg.CheckpointTopic)
		if err != nil {
			return nil, fmt.Errorf("reading checkpoints: %w", err)
		}
		rep.CheckpointSourceNote = "kafka://" + cfg.CheckpointTopic
		rep.CheckpointsSigned = cfg.PublicKey != nil
		for _, c := range cks {
			if cfg.PublicKey != nil && !c.Verify(cfg.PublicKey) {
				rep.add(Problem{c.ChainID, c.Seq, "bad_checkpoint_signature", "checkpoint signature invalid"})
				continue
			}
			h, ok := hashes[c.ChainID][c.Seq]
			switch {
			case !ok:
				rep.add(Problem{c.ChainID, c.Seq, "checkpoint_row_missing",
					"a signed checkpoint names this row but it is gone (rows deleted or tail truncated)"})
			case hex.EncodeToString(h) != c.Hash:
				rep.add(Problem{c.ChainID, c.Seq, "checkpoint_mismatch",
					"row hash differs from the signed checkpoint (chain rewritten)"})
			default:
				rep.CheckpointsVerified++
			}
		}
	}
	if cfg.CrossCheckTopic != "" && len(cfg.Brokers) > 0 {
		kafka, err := readTopicDigests(ctx, cfg.Brokers, cfg.CrossCheckTopic)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", cfg.CrossCheckTopic, err)
		}
		for _, s := range sources {
			d, ok := kafka[partOffset{s.chain, s.offset}]
			switch {
			case !ok:
				rep.add(Problem{s.chain, s.seq, "no_kafka_source", "no Kafka record at this row's offset (row forged in the database)"})
			case d != s.digest:
				rep.add(Problem{s.chain, s.seq, "kafka_source_mismatch", "row content differs from the Kafka record it came from"})
			default:
				rep.RowsCrossChecked++
			}
		}
	}
	rep.OK = len(rep.Problems) == 0
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep, nil
}

type partOffset struct {
	p int32
	o int64
}

// sourceDigest is the SHA-256 of the Kafka record a row came from. Invalid
// records are stored wrapped in an envelope carrying the original bytes.
func sourceDigest(ev, verdict string) [32]byte {
	if verdict == "invalid_record" {
		var env struct {
			Raw string `json:"raw_b64"`
		}
		if json.Unmarshal([]byte(ev), &env) == nil {
			if raw, err := base64.StdEncoding.DecodeString(env.Raw); err == nil {
				return sha256.Sum256(raw)
			}
		}
	}
	return sha256.Sum256([]byte(ev))
}

func readTopicDigests(ctx context.Context, brokers []string, topic string) (map[partOffset][32]byte, error) {
	out := map[partOffset][32]byte{}
	err := consumeAll(ctx, brokers, topic, func(r *kgo.Record) {
		out[partOffset{r.Partition, r.Offset}] = sha256.Sum256(r.Value)
	})
	return out, err
}

// consumeAll reads every partition of topic from the start to its current end.
func consumeAll(ctx context.Context, brokers []string, topic string, fn func(*kgo.Record)) error {
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		return err
	}
	defer cl.Close()
	ends, err := kadm.NewClient(cl).ListEndOffsets(ctx, topic)
	if err != nil {
		return err
	}
	want := map[int32]int64{}
	assign := map[string]map[int32]kgo.Offset{topic: {}}
	ends.Each(func(o kadm.ListedOffset) {
		if o.Err == nil && o.Offset > 0 {
			want[o.Partition] = o.Offset
			assign[topic][o.Partition] = kgo.NewOffset().AtStart()
		}
	})
	if len(want) == 0 {
		return nil
	}
	cl.AddConsumePartitions(assign)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for len(want) > 0 {
		fs := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fs.EachRecord(func(r *kgo.Record) {
			fn(r)
			if end, ok := want[r.Partition]; ok && r.Offset+1 >= end {
				delete(want, r.Partition)
			}
		})
	}
	return nil
}

func columnDrift(ev string, id uuid.UUID, agent, session, tool, verdict string, tier int16, policy string, failed bool) string {
	var e struct {
		Type       string `json:"type"`
		EventID    string `json:"event_id"`
		AgentID    string `json:"agent_id"`
		SessionID  string `json:"session_id"`
		ToolName   string `json:"tool_name"`
		Verdict    string `json:"verdict"`
		Tier       int16  `json:"tier"`
		Policy     string `json:"policy"`
		FailClosed bool   `json:"fail_closed"`
	}
	if err := json.Unmarshal([]byte(ev), &e); err != nil {
		return "event is not valid JSON"
	}
	if e.Type == "invalid_record" {
		e.Verdict = "invalid_record"
	}
	switch {
	case e.EventID != id.String():
		return "event_id column differs from event"
	case e.Verdict != verdict:
		return fmt.Sprintf("verdict column %q differs from event %q", verdict, e.Verdict)
	case e.AgentID != agent, e.SessionID != session, e.ToolName != tool:
		return "agent/session/tool column differs from event"
	case e.Tier != tier, e.Policy != policy, e.FailClosed != failed:
		return "tier/policy/fail_closed column differs from event"
	}
	return ""
}

func readCheckpoints(ctx context.Context, brokers []string, topic string) ([]Checkpoint, error) {
	var out []Checkpoint
	err := consumeAll(ctx, brokers, topic, func(r *kgo.Record) {
		var c Checkpoint
		if json.Unmarshal(r.Value, &c) == nil {
			out = append(out, c)
		}
	})
	return out, err
}
