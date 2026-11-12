package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxCheckBody = 1 << 20

// Handler serves the decision API, the MCP proxy, health and metrics.
//
//	POST /v1/check            decide one tool call (Python SDK, any client)
//	POST|GET|DELETE /mcp/{agent}  MCP Streamable HTTP proxy for one agent
//	GET  /healthz /readyz /metrics
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/check", g.handleCheck)
	mux.HandleFunc("/mcp/{agent}", g.handleMCP)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", g.handleReady)
	mux.Handle("GET /metrics", promhttp.HandlerFor(g.metrics.Registry, promhttp.HandlerOpts{}))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (g *Gateway) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, maxCheckBody))
	if err := dec.Decode(&req); err != nil {
		// Still a verdict, never just an error: a client that ignores status
		// codes must not read a malformed request as permission.
		writeJSON(w, http.StatusBadRequest, block("malformed_request", "high", "Request body is not valid JSON: "+err.Error(), true))
		return
	}
	res := g.Decide(r.Context(), &req)
	w.Header().Set("X-AgentGate-Verdict", res.Verdict)
	w.Header().Set("X-AgentGate-Decision-Us", strconv.FormatInt(res.LatencyUS, 10))
	writeJSON(w, http.StatusOK, res)
}

// handleReady fails only on dependencies without which no call can be
// allowed (state, audit). A down judge is reported but keeps the gateway in
// rotation: the rule path still serves, and escalations already block.
func (g *Gateway) handleReady(w http.ResponseWriter, r *http.Request) {
	status := g.Ready(r.Context())
	code := http.StatusOK
	if status["state"] != "ok" || status["audit"] != "ok" {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, status)
}
