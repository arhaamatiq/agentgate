// Package judge is the gateway's gRPC client for the Tier 2 LLM judge.
//
// It is fail-closed by construction: Evaluate returns a BLOCK verdict for
// every error path (no connection, deadline exceeded, transport error,
// unspecified verdict). Callers never see an error they could mistake for
// permission.
package judge

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	judgev1 "github.com/arhaamatiq/agentgate/gateway/gen/judgev1"
)

type Request = judgev1.EvaluateRequest

type Result struct {
	Allow      bool
	Confidence float64
	Reasoning  string
	Policy     string
	Severity   string
	Model      string
	// FailClosed is true when the BLOCK came from a failure (judge down,
	// timeout, malformed model output) rather than a real judgement.
	FailClosed bool
}

type Judge interface {
	Evaluate(ctx context.Context, req *Request) Result
	Ready(ctx context.Context) error
	Close() error
}

type Client struct {
	conn    *grpc.ClientConn
	rpc     judgev1.JudgeClient
	health  grpc_health_v1.HealthClient
	timeout time.Duration
}

func Dial(address string, timeout time.Duration) (*Client, error) {
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 5 * time.Second}),
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:    conn,
		rpc:     judgev1.NewJudgeClient(conn),
		health:  grpc_health_v1.NewHealthClient(conn),
		timeout: timeout,
	}, nil
}

func failClosed(reason string) Result {
	return Result{
		Policy: "judge_unavailable", Severity: "medium", FailClosed: true,
		Reasoning: reason + " — blocking by default (fail-closed)",
	}
}

func (c *Client) Evaluate(ctx context.Context, req *Request) Result {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.Evaluate(ctx, req)
	if err != nil {
		st, _ := status.FromError(err)
		return failClosed(fmt.Sprintf("Tier 2 judge call failed (%s: %s)", st.Code(), st.Message()))
	}
	switch resp.GetVerdict() {
	case judgev1.Verdict_VERDICT_ALLOW:
		return Result{Allow: true, Confidence: resp.GetConfidence(), Reasoning: resp.GetReasoning(),
			Policy: resp.GetPolicyName(), Severity: resp.GetSeverity(), Model: resp.GetModel()}
	case judgev1.Verdict_VERDICT_BLOCK:
		return Result{Confidence: resp.GetConfidence(), Reasoning: resp.GetReasoning(),
			Policy: resp.GetPolicyName(), Severity: resp.GetSeverity(), Model: resp.GetModel(),
			FailClosed: resp.GetPolicyName() == "tier2_error"}
	default:
		return failClosed("Tier 2 judge returned no verdict")
	}
}

func (c *Client) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.health.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "agentgate.judge.v1.Judge"})
	if err != nil {
		return err
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("judge status %s", resp.GetStatus())
	}
	return nil
}

func (c *Client) Close() error { return c.conn.Close() }

// None is used when no judge is configured: every escalation blocks.
type None struct{}

func (None) Evaluate(context.Context, *Request) Result {
	return failClosed("No Tier 2 judge configured")
}
func (None) Ready(context.Context) error { return nil }
func (None) Close() error                { return nil }
