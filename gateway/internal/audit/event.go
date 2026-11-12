// Package audit streams every gateway decision through Kafka into a
// tamper-evident, append-only PostgreSQL log.
//
//	gateway --(Kafka, idempotent, acks=all)--> auditor --(1 tx per batch)--> Postgres
//
// Each Kafka partition is one hash chain. The auditor stores the Kafka
// offset in the same transaction as the rows, so a crash or rebalance can
// neither drop nor duplicate an event. Rows are linked by
//
//	hash = SHA-256(prev_hash || chain_id (4B BE) || seq (8B BE) || event bytes)
//
// and the auditor publishes Ed25519-signed checkpoints of chain heads to a
// separate Kafka topic. The verifier recomputes every link and checks every
// checkpoint, so it detects an edited row, a deleted row, a truncated tail,
// and even a fully rewritten chain.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Event is one decision. Field order is the wire format; the verifier hashes
// the exact bytes the gateway produced.
type Event struct {
	V          int             `json:"v"`
	EventID    string          `json:"event_id"`
	TS         string          `json:"ts"`
	Gateway    string          `json:"gateway"`
	Source     string          `json:"source"`
	AgentID    string          `json:"agent_id"`
	SessionID  string          `json:"session_id"`
	UserID     string          `json:"user_id,omitempty"`
	ToolName   string          `json:"tool_name"`
	Arguments  json.RawMessage `json:"arguments,omitempty"`
	ArgsSHA256 string          `json:"args_sha256"`
	Verdict    string          `json:"verdict"`
	Tier       int             `json:"tier"`
	Policy     string          `json:"policy"`
	Severity   string          `json:"severity"`
	Reasoning  string          `json:"reasoning"`
	FailClosed bool            `json:"fail_closed"`
	Cached     bool            `json:"cached"`
	LatencyUS  int64           `json:"latency_us"`
}

func ArgsDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ErrUnavailable means the audit pipeline cannot accept a record right now.
// The gateway turns it into a BLOCK: no action executes unaudited.
var ErrUnavailable = errors.New("audit pipeline unavailable")

type Sink interface {
	Record(ctx context.Context, ev *Event) error
	Ready(ctx context.Context) error
	Close(ctx context.Context) error
}

// Discard drops events (audit disabled).
type Discard struct{}

func (Discard) Record(context.Context, *Event) error { return nil }
func (Discard) Ready(context.Context) error          { return nil }
func (Discard) Close(context.Context) error          { return nil }
