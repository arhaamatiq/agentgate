package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	judgev1 "github.com/arhaamatiq/agentgate/gateway/gen/judgev1"
	"github.com/arhaamatiq/agentgate/gateway/internal/audit"
	"github.com/arhaamatiq/agentgate/gateway/internal/judge"
	"github.com/arhaamatiq/agentgate/gateway/internal/rules"
	"github.com/arhaamatiq/agentgate/gateway/internal/state"
)

type fakeJudge struct {
	res   judge.Result
	calls int
	last  *judgev1.EvaluateRequest
}

func (f *fakeJudge) Evaluate(_ context.Context, r *judgev1.EvaluateRequest) judge.Result {
	f.calls++
	f.last = r
	return f.res
}
func (f *fakeJudge) Ready(context.Context) error { return nil }
func (f *fakeJudge) Close() error                { return nil }

type brokenStore struct{ state.Store }

var errDown = errors.New("connection refused")

func (brokenStore) History(context.Context, string, int) ([]state.HistoryEntry, error) {
	return nil, errDown
}
func (brokenStore) AppendHistory(context.Context, string, state.HistoryEntry, int) error {
	return errDown
}
func (brokenStore) CacheGet(context.Context, string) (*state.CachedVerdict, error) {
	return nil, errDown
}
func (brokenStore) CacheSet(context.Context, string, state.CachedVerdict, time.Duration) error {
	return errDown
}
func (brokenStore) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return false, errDown
}

type brokenSink struct{ audit.Discard }

func (brokenSink) Record(context.Context, *audit.Event) error { return audit.ErrUnavailable }

type memSink struct{ events []*audit.Event }

func (m *memSink) Record(_ context.Context, e *audit.Event) error {
	m.events = append(m.events, e)
	return nil
}
func (m *memSink) Ready(context.Context) error { return nil }
func (m *memSink) Close(context.Context) error { return nil }

func testConfig() *Config {
	c := DefaultConfig()
	c.Agents = map[string]AgentPolicy{
		"reporting-agent": {Scope: rules.Scope{Task: "weekly sales report", AllowedOperations: []string{"read"}, AllowedResources: []string{"sales"}}},
	}
	return c
}

func check(agent, tool, args string) *CheckRequest {
	return &CheckRequest{AgentID: agent, ToolName: tool, Arguments: json.RawMessage(args)}
}

const (
	safeCall      = `{"query": "SELECT region, SUM(total) FROM sales GROUP BY region"}`
	ambiguousCall = `{"query": "SELECT * FROM admin_credentials"}`
)

func TestRulePathNeedsNoJudge(t *testing.T) {
	j := &fakeJudge{}
	g := New(testConfig(), j, state.NewMemory(), audit.Discard{}, NewMetrics())
	if r := g.Decide(context.Background(), check("reporting-agent", "execute_sql", safeCall)); r.Verdict != "allow" || r.Tier != 1 {
		t.Fatalf("got %+v", r)
	}
	if r := g.Decide(context.Background(), check("reporting-agent", "execute_sql", `{"query": "DROP TABLE sales"}`)); r.Verdict != "block" || r.Tier != 1 {
		t.Fatalf("got %+v", r)
	}
	if j.calls != 0 {
		t.Fatalf("judge called %d times for deterministic calls", j.calls)
	}
}

func TestEscalationUsesJudgeVerdict(t *testing.T) {
	j := &fakeJudge{res: judge.Result{Allow: true, Policy: "llm_judge", Severity: "low", Reasoning: "fine"}}
	g := New(testConfig(), j, state.NewMemory(), audit.Discard{}, NewMetrics())
	r := g.Decide(context.Background(), check("reporting-agent", "execute_sql", ambiguousCall))
	if r.Verdict != "allow" || r.Tier != 2 || j.calls != 1 {
		t.Fatalf("got %+v after %d judge calls", r, j.calls)
	}
	if j.last.Operation != "read" || j.last.ActionType != "sql" || j.last.Scope.GetTask() != "weekly sales report" {
		t.Fatalf("judge request missing context: %+v", j.last)
	}
}

func TestFailClosed(t *testing.T) {
	down := judge.None{} // stands in for any judge failure: Evaluate returns FailClosed
	cases := []struct {
		name   string
		judge  judge.Judge
		store  state.Store
		sink   audit.Sink
		req    *CheckRequest
		policy string
	}{
		{"judge down", down, state.NewMemory(), audit.Discard{}, check("reporting-agent", "execute_sql", ambiguousCall), "judge_unavailable"},
		{"judge returns tier2_error", &fakeJudge{res: judge.Result{Policy: "tier2_error", FailClosed: true}}, state.NewMemory(), audit.Discard{},
			check("reporting-agent", "execute_sql", ambiguousCall), "tier2_error"},
		{"state store down (escalation)", &fakeJudge{res: judge.Result{Allow: true}}, brokenStore{}, audit.Discard{},
			check("reporting-agent", "execute_sql", ambiguousCall), "state_unavailable"},
		{"state store down (allowed call)", down, brokenStore{}, audit.Discard{}, check("reporting-agent", "execute_sql", safeCall), "state_unavailable"},
		{"audit pipeline down", down, state.NewMemory(), brokenSink{}, check("reporting-agent", "execute_sql", safeCall), "audit_unavailable"},
		{"unknown agent", down, state.NewMemory(), audit.Discard{}, check("intruder", "execute_sql", safeCall), "unknown_agent"},
		{"arguments not an object", down, state.NewMemory(), audit.Discard{}, check("reporting-agent", "execute_sql", `["DROP TABLE sales"]`), "malformed_arguments"},
		{"argument type the rules can't analyze", down, state.NewMemory(), audit.Discard{}, check("reporting-agent", "execute_sql", `{"query": {"x": 1}}`), rules.PolicyRuleError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := New(testConfig(), c.judge, c.store, c.sink, NewMetrics())
			r := g.Decide(context.Background(), c.req)
			if r.Verdict != "block" || r.Policy != c.policy {
				t.Fatalf("want block/%s, got %+v", c.policy, r)
			}
		})
	}
}

func TestInlineScopeRequiresOptIn(t *testing.T) {
	c := testConfig()
	g := New(c, judge.None{}, state.NewMemory(), audit.Discard{}, NewMetrics())
	req := check("anyone", "execute_sql", safeCall)
	req.Scope = &rules.Scope{AllowedOperations: []string{"read", "destructive"}}
	if r := g.Decide(context.Background(), req); r.Verdict != "block" || r.Policy != "inline_scope_disabled" {
		t.Fatalf("got %+v", r)
	}
}

func TestTrajectorySharedAcrossReplicas(t *testing.T) {
	// Two gateways sharing one store: the judge on replica B sees the call
	// made through replica A.
	shared := state.NewMemory()
	ja, jb := &fakeJudge{res: judge.Result{Allow: true}}, &fakeJudge{res: judge.Result{Allow: true}}
	a := New(testConfig(), ja, shared, audit.Discard{}, NewMetrics())
	b := New(testConfig(), jb, shared, audit.Discard{}, NewMetrics())
	r1 := check("reporting-agent", "execute_sql", safeCall)
	r1.SessionID = "s1"
	a.Decide(context.Background(), r1)
	r2 := check("reporting-agent", "execute_sql", ambiguousCall)
	r2.SessionID = "s1"
	b.Decide(context.Background(), r2)
	if jb.calls != 1 || len(jb.last.History) != 1 || jb.last.History[0].Verdict != "allow" {
		t.Fatalf("replica B judge did not see replica A's call: %+v", jb.last.GetHistory())
	}
}

func TestEveryDecisionIsAudited(t *testing.T) {
	sink := &memSink{}
	g := New(testConfig(), judge.None{}, state.NewMemory(), sink, NewMetrics())
	for _, args := range []string{safeCall, ambiguousCall, `{"query": "DROP TABLE sales"}`} {
		g.Decide(context.Background(), check("reporting-agent", "execute_sql", args))
	}
	g.Decide(context.Background(), check("intruder", "read_file", `{"path": "/etc/passwd"}`))
	if len(sink.events) != 4 {
		t.Fatalf("want 4 audit events, got %d", len(sink.events))
	}
	for _, e := range sink.events {
		if e.EventID == "" || e.Verdict == "" || e.ArgsSHA256 == "" {
			t.Fatalf("incomplete event %+v", e)
		}
	}
}
