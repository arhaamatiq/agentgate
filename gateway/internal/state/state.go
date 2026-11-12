// Package state holds what gateway replicas must share:
//
//   - Session trajectories. The judge sees the last 10 calls of a session to
//     catch read-then-exfiltrate chains; with several replicas behind a load
//     balancer, consecutive calls land on different pods.
//   - Judge verdicts. An LLM judgement costs ~1-3 s and money; an identical
//     escalation (same scope, call, and trajectory) reuses it.
//   - Per-agent rate limits (scope max_rate), enforced across replicas.
//
// Memory is a single-process implementation; Redis is the shared one.
package state

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type HistoryEntry struct {
	ToolName      string `json:"tool_name"`
	ArgumentsJSON string `json:"arguments_json"`
	Verdict       string `json:"verdict"`
}

type CachedVerdict struct {
	Allow      bool    `json:"allow"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	Policy     string  `json:"policy"`
	Severity   string  `json:"severity"`
	Model      string  `json:"model"`
}

type Store interface {
	History(ctx context.Context, session string, n int) ([]HistoryEntry, error)
	AppendHistory(ctx context.Context, session string, e HistoryEntry, keep int) error
	CacheGet(ctx context.Context, key string) (*CachedVerdict, error)
	CacheSet(ctx context.Context, key string, v CachedVerdict, ttl time.Duration) error
	// Allow records one call and reports whether the key is within limit
	// calls per window (sliding window).
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
	Ping(ctx context.Context) error
	Close() error
}

// ---------------------------------------------------------------- memory

type Memory struct {
	mu      sync.Mutex
	history map[string][]HistoryEntry
	cache   map[string]memCached
	windows map[string][]time.Time
}

type memCached struct {
	v   CachedVerdict
	exp time.Time
}

func NewMemory() *Memory {
	return &Memory{history: map[string][]HistoryEntry{}, cache: map[string]memCached{}, windows: map[string][]time.Time{}}
}

func (m *Memory) History(_ context.Context, session string, n int) ([]HistoryEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.history[session]
	if len(h) > n {
		h = h[len(h)-n:]
	}
	return append([]HistoryEntry(nil), h...), nil
}

func (m *Memory) AppendHistory(_ context.Context, session string, e HistoryEntry, keep int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := append(m.history[session], e)
	if len(h) > keep {
		h = h[len(h)-keep:]
	}
	m.history[session] = h
	return nil
}

func (m *Memory) CacheGet(_ context.Context, key string) (*CachedVerdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cache[key]
	if !ok || time.Now().After(c.exp) {
		return nil, nil
	}
	v := c.v
	return &v, nil
}

func (m *Memory) CacheSet(_ context.Context, key string, v CachedVerdict, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[key] = memCached{v, time.Now().Add(ttl)}
	return nil
}

func (m *Memory) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	w := m.windows[key][:0]
	for _, t := range m.windows[key] {
		if now.Sub(t) < window {
			w = append(w, t)
		}
	}
	w = append(w, now)
	m.windows[key] = w
	return len(w) <= limit, nil
}

func (m *Memory) Ping(context.Context) error { return nil }
func (m *Memory) Close() error               { return nil }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
