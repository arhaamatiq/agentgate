// demo-mcp-server: a minimal MCP server with "dangerous" tools that do
// nothing but record that they ran. The fail-closed tests assert against
// /executed: a call the gateway blocked must never appear there.
//
//	demo-mcp-server http  [--addr :9000]   Streamable HTTP at /mcp
//	demo-mcp-server stdio                  newline-delimited JSON-RPC
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type executed struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

var (
	mu   sync.Mutex
	log_ []executed
)

func tool(name, desc string, props map[string]string) map[string]any {
	p := map[string]any{}
	req := []string{}
	for k, v := range props {
		p[k] = map[string]string{"type": "string", "description": v}
		req = append(req, k)
	}
	return map[string]any{"name": name, "description": desc,
		"inputSchema": map[string]any{"type": "object", "properties": p, "required": req}}
}

var tools = []map[string]any{
	tool("execute_sql", "Run a SQL query against the company database.", map[string]string{"query": "SQL"}),
	tool("read_file", "Read a file.", map[string]string{"path": "file path"}),
	tool("write_file", "Write a file.", map[string]string{"path": "file path", "content": "content"}),
	tool("http_request", "Make an HTTP request.", map[string]string{"url": "URL", "method": "HTTP method"}),
	tool("send_email", "Send an email.", map[string]string{"to": "recipient", "subject": "subject", "body": "body"}),
	tool("run_command", "Run a shell command.", map[string]string{"cmd": "command"}),
}

func handle(m *message) []byte {
	if len(m.ID) == 0 {
		return nil // notification
	}
	var result any
	switch m.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "agentgate-demo-tools", "version": "1.0.0"},
		}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(m.Params, &p)
		mu.Lock()
		log_ = append(log_, executed{p.Name, p.Arguments})
		mu.Unlock()
		result = map[string]any{"content": []map[string]string{{"type": "text",
			"text": fmt.Sprintf("[demo] %s executed with %s", p.Name, string(p.Arguments))}}}
	default:
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID,
			"error": map[string]any{"code": -32601, "message": "method not found"}})
		return b
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
	return b
}

func main() {
	mode := "http"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	addr := fs.String("addr", ":9000", "listen address (http mode)")
	if len(os.Args) > 2 {
		_ = fs.Parse(os.Args[2:])
	}
	if mode == "stdio" {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var m message
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			if out := handle(&m); out != nil {
				fmt.Println(string(out))
			}
		}
		return
	}
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var m message
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if m.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", uuid.NewString())
		}
		out := handle(&m)
		if out == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	http.HandleFunc("/executed", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodDelete {
			log_ = nil
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"count": len(log_), "calls": log_})
	})
	log.Printf("demo MCP server on %s/mcp", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
