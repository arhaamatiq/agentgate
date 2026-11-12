package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

type ProducerConfig struct {
	Brokers    []string
	Topic      string
	Partitions int32
	// Sync waits for the broker ack before the decision is released. Async
	// releases immediately and blocks new decisions only when the buffer
	// backs up (Kafka unreachable).
	Sync        bool
	MaxBuffered int
}

type Producer struct {
	cl          *kgo.Client
	cfg         ProducerConfig
	failed      atomic.Int64
	acked       atomic.Int64
	OnDelivered func(err error)
}

func NewProducer(ctx context.Context, cfg ProducerConfig) (*Producer, error) {
	if cfg.MaxBuffered <= 0 {
		cfg.MaxBuffered = 100_000
	}
	linger := 2 * time.Millisecond
	if cfg.Sync {
		linger = 0
	}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DefaultProduceTopic(cfg.Topic),
		kgo.RequiredAcks(kgo.AllISRAcks()), // idempotent producer is the default with all-ISR acks
		kgo.ProducerLinger(linger),
		kgo.MaxBufferedRecords(cfg.MaxBuffered),
		kgo.ProducerBatchCompression(kgo.Lz4Compression()),
	)
	if err != nil {
		return nil, err
	}
	p := &Producer{cl: cl, cfg: cfg}
	if err := EnsureTopic(ctx, cl, cfg.Topic, cfg.Partitions, nil); err != nil {
		slog.Warn("audit topic check failed (will retry on produce)", "topic", cfg.Topic, "err", err)
	}
	return p, nil
}

// EnsureTopic creates a topic if it does not exist.
func EnsureTopic(ctx context.Context, cl *kgo.Client, topic string, partitions int32, configs map[string]*string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	adm := kadm.NewClient(cl)
	resp, err := adm.CreateTopics(ctx, partitions, -1, configs, topic)
	if err != nil {
		return err
	}
	for _, r := range resp {
		if r.Err != nil && !errors.Is(r.Err, kerr.TopicAlreadyExists) {
			return r.Err
		}
	}
	return nil
}

func (p *Producer) Record(ctx context.Context, ev *Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	rec := &kgo.Record{Key: []byte(ev.SessionID), Value: b}
	if p.cfg.Sync {
		// Bounded: an unreachable broker becomes a fast BLOCK, not a hang.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := p.cl.ProduceSync(ctx, rec).FirstErr(); err != nil {
			p.failed.Add(1)
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		p.acked.Add(1)
		return nil
	}
	// Leave headroom so a burst can't push the buffer to its hard limit.
	if p.cl.BufferedProduceRecords() >= int64(p.cfg.MaxBuffered)*9/10 {
		return fmt.Errorf("%w: %d records buffered, broker not draining", ErrUnavailable, p.cl.BufferedProduceRecords())
	}
	p.cl.TryProduce(context.Background(), rec, func(_ *kgo.Record, err error) {
		if err != nil {
			p.failed.Add(1)
			slog.Error("audit record delivery failed", "event_id", ev.EventID, "err", err)
		} else {
			p.acked.Add(1)
		}
		if p.OnDelivered != nil {
			p.OnDelivered(err)
		}
	})
	return nil
}

func (p *Producer) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return p.cl.Ping(ctx)
}

func (p *Producer) Stats() (acked, failed, buffered int64) {
	return p.acked.Load(), p.failed.Load(), p.cl.BufferedProduceRecords()
}

// Close flushes buffered records, then closes the client.
func (p *Producer) Close(ctx context.Context) error {
	err := p.cl.Flush(ctx)
	p.cl.Close()
	return err
}
