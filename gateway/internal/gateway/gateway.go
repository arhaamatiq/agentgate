// Package gateway is AgentGate's decision service: a deterministic rule path
// in-process, gRPC escalation to the LLM judge for ambiguous calls, shared
// session state in Redis, and every decision streamed to the audit log.
//
// Fail-closed is a property of the pipeline, not of one component. Every
// error path, including an unknown agent, malformed arguments, a rule panic,
// the judge being down or slow, Redis being down, and the audit pipeline
// being unavailable, produces BLOCK. If the gateway process itself is down,
// agents cannot reach tools at all: the MCP servers are only routable
// through it, and the Python SDK blocks when it cannot get a verdict.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	judgev1 "github.com/arhaamatiq/agentgate/gateway/gen/judgev1"
	"github.com/arhaamatiq/agentgate/gateway/internal/audit"
	"github.com/arhaamatiq/agentgate/gateway/internal/judge"
	"github.com/arhaamatiq/agentgate/gateway/internal/pyjson"
	"github.com/arhaamatiq/agentgate/gateway/internal/rules"
	"github.com/arhaamatiq/agentgate/gateway/internal/state"
)

type Gateway struct {
	cfg     *Config
	engine  *rules.Engine
	judge   judge.Judge
	store   state.Store
	audit   audit.Sink
	metrics *Metrics
}

func New(cfg *Config, j judge.Judge, st state.Store, sink audit.Sink, m *Metrics) *Gateway {
	return &Gateway{cfg: cfg, engine: rules.New(cfg.Tools), judge: j, store: st, audit: sink, metrics: m}
}

type CheckRequest struct {
	AgentID   string          `json:"agent_id"`
	SessionID string          `json:"session_id"`
	UserID    string          `json:"user_id"`
	Task      string          `json:"task"`
	Scope     *rules.Scope    `json:"scope"`
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments"`

	source string
}

type Result struct {
	DecisionID string `json:"decision_id"`
	Verdict    string `json:"verdict"`
	Tier       int    `json:"tier"`
	Policy     string `json:"policy"`
	Severity   string `json:"severity"`
	Reasoning  string `json:"reasoning"`
	FailClosed bool   `json:"fail_closed"`
	Cached     bool   `json:"cached"`
	LatencyUS  int64  `json:"latency_us"`
}

func block(policy, severity, reasoning string, failClosed bool) Result {
	return Result{Verdict: "block", Tier: 1, Policy: policy, Severity: severity, Reasoning: reasoning, FailClosed: failClosed}
}

// Decide returns ALLOW or BLOCK for one tool call. It never returns an error.
func (g *Gateway) Decide(ctx context.Context, req *CheckRequest) (res Result) {
	start := time.Now()
	id, _ := uuid.NewV7()
	if req.SessionID == "" {
		req.SessionID = "agent:" + req.AgentID
	}
	if req.source == "" {
		req.source = "api"
	}
	defer func() {
		if r := recover(); r != nil { // last line of defense
			slog.Error("decision panic", "err", r)
			res = block("gateway_error", "high", fmt.Sprintf("Gateway error (%v) — blocking by default (fail-closed)", r), true)
		}
		res.DecisionID = id.String()
		res.LatencyUS = time.Since(start).Microseconds()
		g.finish(ctx, req, &res)
	}()

	scope, task, r, ok := g.resolveScope(req)
	if !ok {
		return r
	}
	args, err := pyjson.ParseObject(orEmpty(req.Arguments))
	if err != nil {
		return block("malformed_arguments", "high", "Tool arguments are not a JSON object ("+err.Error()+")", true)
	}
	if scope != nil && scope.MaxRate > 0 {
		allowed, err := g.store.Allow(ctx, "agent:"+req.AgentID, scope.MaxRate, time.Minute)
		if err != nil {
			return block("state_unavailable", "high", "Rate-limit state unavailable ("+err.Error()+") — blocking by default (fail-closed)", true)
		}
		if !allowed {
			return block("rate_limit", "high", "Rate limit exceeded for agent "+req.AgentID, false)
		}
	}

	tc := rules.NewToolCall(req.ToolName, args)
	d := g.engine.Evaluate(tc, scope)
	switch d.Verdict {
	case rules.Allow, rules.Block:
		return Result{Verdict: string(d.Verdict), Tier: 1, Policy: d.Policy, Severity: string(d.Severity),
			Reasoning: d.Reasoning, FailClosed: d.Policy == rules.PolicyRuleError}
	}
	return g.escalate(ctx, req, scope, task, d, id.String())
}

func orEmpty(b json.RawMessage) []byte {
	if len(b) == 0 || string(b) == "null" {
		return []byte("{}")
	}
	return b
}

func (g *Gateway) resolveScope(req *CheckRequest) (*rules.Scope, string, Result, bool) {
	if req.Scope != nil {
		if !g.cfg.AllowInlineScope {
			return nil, "", block("inline_scope_disabled", "high", "This gateway only serves agents declared in its policy file", false), false
		}
		s := *req.Scope
		task := req.Task
		return &s, task, Result{}, true
	}
	if pol, ok := g.cfg.Agents[req.AgentID]; ok {
		s := pol.Scope
		return &s, req.Task, Result{}, true
	}
	if len(g.cfg.Agents) > 0 || !g.cfg.AllowInlineScope {
		return nil, "", block("unknown_agent", "high", fmt.Sprintf("No policy for agent %q — blocking by default", req.AgentID), false), false
	}
	return nil, req.Task, Result{}, true
}

func (g *Gateway) escalate(ctx context.Context, req *CheckRequest, scope *rules.Scope, task string, d rules.Decision, id string) Result {
	hist, err := g.store.History(ctx, req.SessionID, g.cfg.State.HistorySize)
	if err != nil {
		return block("state_unavailable", "high", "Session trajectory unavailable ("+err.Error()+") — blocking by default (fail-closed)", true)
	}
	jr := &judgev1.EvaluateRequest{
		RequestId: id, AgentId: req.AgentID, UserId: req.UserID, SessionId: req.SessionID, Task: task,
		ToolName: req.ToolName, ArgumentsJson: string(orEmpty(req.Arguments)),
		ActionType: d.ActionType, Operation: d.Operation, Tier1Reasoning: d.Reasoning,
	}
	if scope != nil {
		jr.Scope = &judgev1.Scope{Task: scope.Task, AllowedOperations: scope.AllowedOperations,
			AllowedResources: scope.AllowedResources, DenyOperations: scope.DenyOperations}
	}
	for _, h := range hist {
		jr.History = append(jr.History, &judgev1.HistoryEntry{ToolName: h.ToolName, ArgumentsJson: h.ArgumentsJSON, Verdict: h.Verdict})
	}

	key := cacheKey(jr)
	useCache := g.cfg.State.JudgeCacheTTL > 0
	if c, err := g.store.CacheGet(ctx, key); useCache && err == nil && c != nil {
		g.metrics.JudgeCache.WithLabelValues("hit").Inc()
		v := "block"
		if c.Allow {
			v = "allow"
		}
		return Result{Verdict: v, Tier: 2, Policy: c.Policy, Severity: c.Severity, Reasoning: c.Reasoning, Cached: true}
	}
	if useCache {
		g.metrics.JudgeCache.WithLabelValues("miss").Inc()
	}

	t0 := time.Now()
	jres := g.judge.Evaluate(ctx, jr)
	outcome := "block"
	switch {
	case jres.FailClosed:
		outcome = "fail_closed"
	case jres.Allow:
		outcome = "allow"
	}
	g.metrics.JudgeCalls.WithLabelValues(outcome).Inc()
	g.metrics.JudgeLatency.Observe(time.Since(t0).Seconds())

	if useCache && !jres.FailClosed {
		_ = g.store.CacheSet(ctx, key, state.CachedVerdict{Allow: jres.Allow, Confidence: jres.Confidence,
			Reasoning: jres.Reasoning, Policy: jres.Policy, Severity: jres.Severity, Model: jres.Model}, g.cfg.State.JudgeCacheTTL)
	}
	v := "block"
	if jres.Allow && !jres.FailClosed {
		v = "allow"
	}
	return Result{Verdict: v, Tier: 2, Policy: jres.Policy, Severity: jres.Severity, Reasoning: jres.Reasoning, FailClosed: jres.FailClosed}
}

// cacheKey covers every input of the judge prompt, including the trajectory,
// so a verdict is only reused for an identical judgement.
func cacheKey(r *judgev1.EvaluateRequest) string {
	b, _ := json.Marshal([]any{r.AgentId, r.UserId, r.Task, r.Scope, r.ToolName, r.ArgumentsJson,
		r.ActionType, r.Operation, r.Tier1Reasoning, r.History})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// finish records trajectory and audit state. Failing either one turns an
// ALLOW into a BLOCK: no call executes unrecorded.
func (g *Gateway) finish(ctx context.Context, req *CheckRequest, res *Result) {
	args := orEmpty(req.Arguments)
	if err := g.store.AppendHistory(ctx, req.SessionID, state.HistoryEntry{
		ToolName: req.ToolName, ArgumentsJSON: string(args), Verdict: res.Verdict,
	}, g.cfg.State.HistorySize); err != nil && res.Verdict == "allow" {
		*res = block("state_unavailable", "high", "Session trajectory could not be recorded ("+err.Error()+") — blocking by default (fail-closed)", true)
	}

	ev := &audit.Event{
		V: 1, EventID: res.DecisionID, TS: time.Now().UTC().Format(time.RFC3339Nano), Gateway: g.cfg.GatewayID,
		Source: req.source, AgentID: req.AgentID, SessionID: req.SessionID, UserID: req.UserID,
		ToolName: req.ToolName, ArgsSHA256: audit.ArgsDigest(args), Verdict: res.Verdict, Tier: res.Tier,
		Policy: res.Policy, Severity: res.Severity, Reasoning: res.Reasoning, FailClosed: res.FailClosed,
		Cached: res.Cached, LatencyUS: res.LatencyUS,
	}
	if g.cfg.includeArguments() && json.Valid(args) {
		ev.Arguments = args
	}
	if err := g.audit.Record(ctx, ev); err != nil {
		g.metrics.AuditFailures.Inc()
		slog.Error("audit record rejected", "decision_id", res.DecisionID, "err", err)
		if res.Verdict == "allow" {
			id, lat := res.DecisionID, res.LatencyUS
			*res = block("audit_unavailable", "high", "Audit pipeline unavailable ("+err.Error()+") — blocking by default (fail-closed)", true)
			res.DecisionID, res.LatencyUS = id, lat
		}
	}
	g.metrics.Decisions.WithLabelValues(res.Verdict, fmt.Sprint(res.Tier), res.Policy).Inc()
	g.metrics.DecisionLatency.WithLabelValues(fmt.Sprint(res.Tier)).Observe(float64(res.LatencyUS) / 1e6)
	if res.FailClosed {
		g.metrics.FailClosed.WithLabelValues(res.Policy).Inc()
	}
}

// Ready reports whether every dependency is reachable.
func (g *Gateway) Ready(ctx context.Context) map[string]string {
	out := map[string]string{}
	check := func(name string, err error) {
		if err != nil {
			out[name] = err.Error()
		} else {
			out[name] = "ok"
		}
	}
	check("judge", g.judge.Ready(ctx))
	check("state", g.store.Ping(ctx))
	check("audit", g.audit.Ready(ctx))
	return out
}
