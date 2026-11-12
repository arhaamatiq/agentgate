package gateway

// MCP gateway. Agents connect to /mcp/{agent} (Streamable HTTP) or run the
// gateway as a stdio wrapper around a local MCP server. Every tools/call is
// decided before it is forwarded; a blocked call never reaches the server.
// Blocked calls come back as a tool result with isError=true (the MCP
// convention for tool failures), so the model sees why and can adjust.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const maxMCPBody = 4 << 20

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (m *rpcMessage) isRequest() bool {
	return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
}

// blockedResult is the JSON-RPC response for a blocked tools/call.
func blockedResult(id json.RawMessage, res Result) []byte {
	text := fmt.Sprintf("Blocked by AgentGate (%s): %s [decision %s]", res.Policy, res.Reasoning, res.DecisionID)
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"content":           []map[string]string{{"type": "text", "text": text}},
			"isError":           true,
			"structuredContent": map[string]any{"agentgate": res},
		},
	})
	return b
}

func rpcError(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	return b
}

// decideMessage returns a blocked response for msg, or nil to forward it.
func (g *Gateway) decideMessage(ctx context.Context, agent, session, user string, msg *rpcMessage) []byte {
	if msg.Method != "tools/call" {
		return nil
	}
	var p toolCallParams
	if err := json.Unmarshal(msg.Params, &p); err != nil || p.Name == "" {
		return rpcError(msg.ID, -32602, "AgentGate: tools/call params must include a tool name")
	}
	res := g.Decide(ctx, &CheckRequest{
		AgentID: agent, SessionID: session, UserID: user, ToolName: p.Name, Arguments: p.Arguments, source: "mcp",
	})
	if res.Verdict == "allow" {
		return nil
	}
	return blockedResult(msg.ID, res)
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	agent := r.PathValue("agent")
	pol, ok := g.cfg.Agents[agent]
	if !ok {
		writeRaw(w, http.StatusNotFound, rpcError(nil, -32001, fmt.Sprintf("AgentGate: no policy for agent %q", agent)))
		return
	}
	name := pol.Upstream
	if name == "" {
		name = "default"
	}
	upstream := g.cfg.MCP.Upstreams[name]
	if upstream == "" {
		writeRaw(w, http.StatusBadGateway, rpcError(nil, -32002, "AgentGate: no upstream MCP server configured for this agent"))
		return
	}

	var body []byte
	if r.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxMCPBody+1))
		if err != nil || len(body) > maxMCPBody {
			writeRaw(w, http.StatusRequestEntityTooLarge, rpcError(nil, -32600, "AgentGate: request too large"))
			return
		}
		session := "mcp:" + agent + ":" + r.Header.Get("Mcp-Session-Id")
		user := r.Header.Get("X-AgentGate-User")
		if resp := g.screen(r.Context(), agent, session, user, body); resp != nil {
			writeRaw(w, http.StatusOK, resp)
			return
		}
	}
	g.forward(w, r, upstream, body)
}

// screen decides every tools/call in a POST body. A single blocked call is
// answered directly. A batch containing a blocked call is refused as a whole
// (JSON-RPC batching was removed from MCP in 2025-06-18; this keeps old
// clients safe without partially executing a batch).
func (g *Gateway) screen(ctx context.Context, agent, session, user string, body []byte) []byte {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var batch []rpcMessage
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return rpcError(nil, -32700, "AgentGate: invalid JSON-RPC batch")
		}
		var blocked []byte
		for i := range batch {
			if resp := g.decideMessage(ctx, agent, session, user, &batch[i]); resp != nil && blocked == nil {
				blocked = resp
			}
		}
		if blocked == nil {
			return nil
		}
		var out []json.RawMessage
		for i := range batch {
			if batch[i].isRequest() {
				out = append(out, rpcError(batch[i].ID, -32001, "AgentGate: batch refused because it contains a blocked tools/call"))
			}
		}
		b, _ := json.Marshal(out)
		return b
	}
	var msg rpcMessage
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		return rpcError(nil, -32700, "AgentGate: invalid JSON-RPC message")
	}
	return g.decideMessage(ctx, agent, session, user, &msg)
}

var hopHeaders = []string{"Content-Type", "Accept", "Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-Id"}

var upstreamClient = &http.Client{Transport: &http.Transport{
	MaxIdleConnsPerHost: 256, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 60 * time.Second,
}}

func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, upstream string, body []byte) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, rd)
	if err != nil {
		writeRaw(w, http.StatusBadGateway, rpcError(nil, -32002, "AgentGate: bad upstream URL"))
		return
	}
	for _, h := range append(hopHeaders, g.cfg.MCP.ForwardHeaders...) {
		if v := r.Header.Values(h); len(v) > 0 {
			req.Header[http.CanonicalHeaderKey(h)] = v
		}
	}
	resp, err := upstreamClient.Do(req)
	if err != nil {
		slog.Error("upstream MCP request failed", "upstream", upstream, "err", err)
		writeRaw(w, http.StatusBadGateway, rpcError(nil, -32002, "AgentGate: upstream MCP server unreachable"))
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Connection") {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	// Stream: MCP responses may be Server-Sent Events.
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func writeRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// RunStdio wraps a local stdio MCP server: the agent talks to this process
// over stdin/stdout, and only allowed tools/call messages reach the child.
func (g *Gateway) RunStdio(ctx context.Context, agent string, argv []string, in io.Reader, out io.Writer) error {
	if _, ok := g.cfg.Agents[agent]; !ok {
		return fmt.Errorf("no policy for agent %q", agent)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var mu sync.Mutex
	emit := func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = out.Write(append(b, '\n'))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(childOut)
		sc.Buffer(make([]byte, 1<<20), maxMCPBody*4)
		for sc.Scan() {
			emit(append([]byte(nil), sc.Bytes()...))
		}
	}()
	session := fmt.Sprintf("stdio:%s:%d", agent, os.Getpid())
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), maxMCPBody*4)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if resp := g.screen(ctx, agent, session, "", line); resp != nil {
			emit(resp)
			continue
		}
		if _, err := childIn.Write(append(append([]byte(nil), line...), '\n')); err != nil {
			slog.Error("write to MCP server failed", "err", err)
			break
		}
	}
	_ = childIn.Close()
	<-done
	return cmd.Wait()
}
