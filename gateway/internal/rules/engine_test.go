package rules

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"

	"github.com/arhaamatiq/agentgate/gateway/internal/pyjson"
)

func call(t testing.TB, name, args string) *ToolCall {
	t.Helper()
	o, err := pyjson.ParseObject([]byte(args))
	if err != nil {
		t.Fatal(err)
	}
	return NewToolCall(name, o)
}

func TestFailClosedOnRuleError(t *testing.T) {
	// A non-string query reaches string-only analysis; the reference raises.
	d := New(nil).Evaluate(call(t, "execute_sql", `{"query": ["DROP TABLE users"]}`), nil)
	if d.Verdict != Block || d.Policy != PolicyRuleError {
		t.Fatalf("want fail-closed BLOCK, got %+v", d)
	}
}

func TestFailClosedOnPanic(t *testing.T) {
	// Any panic inside evaluation, not just the ones we anticipate, blocks.
	testHook = func(*ToolCall) { panic("injected fault") }
	defer func() { testHook = nil }()
	d := New(nil).Evaluate(call(t, "read_file", `{"path": "/app/data/x.csv"}`), nil)
	if d.Verdict != Block || d.Policy != PolicyRuleError {
		t.Fatalf("want fail-closed BLOCK, got %+v", d)
	}
}

func TestBasicDecisions(t *testing.T) {
	e := New(nil)
	scope := &Scope{Task: "Q4 report", AllowedOperations: []string{"read"}, AllowedResources: []string{"sales"}}
	cases := []struct {
		name, args string
		want       Verdict
	}{
		{"execute_sql", `{"query": "SELECT region, SUM(total) FROM sales GROUP BY region"}`, Allow},
		{"execute_sql", `{"query": "DROP TABLE sales"}`, Block},
		{"execute_sql", `{"query": "SELECT * FROM admin_credentials"}`, Escalate},
		{"read_file", `{"path": "../../etc/passwd"}`, Block},
		{"http_request", `{"url": "http://169.254.169.254/latest/meta-data/"}`, Block},
	}
	for _, c := range cases {
		if d := e.Evaluate(call(t, c.name, c.args), scope); d.Verdict != c.want {
			t.Errorf("%s %s: got %s (%s: %s), want %s", c.name, c.args, d.Verdict, d.Policy, d.Reasoning, c.want)
		}
	}
}

func TestToolVerbScopes(t *testing.T) {
	e := New(nil)
	cases := []struct {
		ops, deny  []string
		name, args string
		authorized bool
	}{
		{[]string{"delete"}, nil, "delete_file", `{"path": "/tmp/old.tmp"}`, true},
		{[]string{"delete"}, nil, "deleteFile", `{"path": "/tmp/old.tmp"}`, true},
		{[]string{"list"}, nil, "list_directory", `{"path": "/mnt/shared"}`, true},
		{[]string{"restart"}, nil, "restart_service", `{"service": "api"}`, true},
		{[]string{"export"}, nil, "export_data", `{"query": "SELECT * FROM orders", "destination": "s3://r"}`, true},
		{[]string{"delete"}, nil, "write_file", `{"path": "/tmp/x", "content": "x"}`, false},
		{[]string{"delete"}, nil, "execute_sql", `{"query": "DROP TABLE users"}`, false},
		{[]string{"delete"}, nil, "delete_records", `{"query": "DROP TABLE users"}`, false},
		{[]string{"list"}, nil, "list_and_delete_files", `{"path": "/mnt/shared"}`, false},
		{[]string{"fetch"}, nil, "fetch_url", `{"url": "https://example.com"}`, false},
		{[]string{"run"}, nil, "run_command", `{"cmd": "ls"}`, false},
		{[]string{"write"}, []string{"delete"}, "delete_file", `{"path": "/tmp/x"}`, false},
	}
	for _, c := range cases {
		scope := &Scope{Task: "t", AllowedOperations: c.ops, DenyOperations: c.deny}
		d := e.Evaluate(call(t, c.name, c.args), scope)
		if got := d.Policy != "scope_operation"; got != c.authorized {
			t.Errorf("ops=%v deny=%v %s: got %s/%s, want authorized=%v", c.ops, c.deny, c.name, d.Verdict, d.Policy, c.authorized)
		}
	}
}

func TestGrantedLocations(t *testing.T) {
	cases := []struct {
		path, op string
		granted  []string
		want     Verdict
	}{
		{"/var/log/old/2024-01-01.log", "delete", []string{"/var/log/old/"}, Escalate},
		{"/etc/app/config.yaml", "read", []string{"/etc/app/config.yaml"}, Escalate},
		{"/backups/db/backup_2022.sql", "delete", []string{"/backups/db/"}, Escalate},
		{"/var/log/nginx/access.log", "read", []string{"/var/log/nginx"}, Escalate},
		{"/var/log/app/./x.log", "read", []string{"/var/log/app"}, Escalate},
		{"/etc/app/secrets.yaml", "read", []string{"/etc/app/"}, Block},
		{"/etc/app/nginx.conf", "write", []string{"/etc/app/"}, Block},
		{"/var/log/app/../../../etc/shadow", "read", []string{"/var/log/app/"}, Block},
		{"/var/log/app/x%2elog", "read", []string{"/var/log/app/"}, Block},
		{"/etc/nginx/site.conf", "read", []string{"/etc/"}, Block},
		{"/var/log/syslog", "read", []string{"/var"}, Block},
		{"/var/log/app.log", "read", []string{"/"}, Block},
		{"/var/log/apps/x.log", "read", []string{"/var/log/app"}, Block},
		{"/var/log", "read", []string{"/var/log/app/"}, Block},
		{"/var/log/App/x.log", "read", []string{"/var/log/app/"}, Block},
		{"/var/log/app/x.log", "read", []string{"var/log/app"}, Block},
		{"/var/log/app/old", "delete", []string{"/var/log/app/"}, Block},
		{"/var/log/app/*.log", "delete", []string{"/var/log/app/"}, Block},
	}
	for _, c := range cases {
		if a := analyzeFilesystem(c.path, c.op, c.granted); a.verdict != c.want {
			t.Errorf("%s %s granted=%v: got %s (%s), want %s", c.op, c.path, c.granted, a.verdict, a.reasoning, c.want)
		}
	}
	scope := &Scope{Task: "t", AllowedOperations: []string{"delete"}, AllowedResources: []string{"/var/log/old/"}}
	d := New(nil).Evaluate(call(t, "delete_file", `{"path": "/var/log/old/2024-01-01.log"}`), scope)
	if d.Verdict != Escalate || d.Policy != "filesystem_analysis" {
		t.Errorf("engine: got %s/%s, want escalate/filesystem_analysis", d.Verdict, d.Policy)
	}
}

func TestFileToolOperations(t *testing.T) {
	e := New(nil)
	scope := &Scope{Task: "t", AllowedOperations: []string{"read"}}
	args := `{"path": "/srv/data/a.txt", "destination": "/srv/data/b.txt", "to": "x@example.com"}`
	for _, name := range []string{"create_file", "edit_file", "move_file", "rename_file", "append_to_file", "copy_file",
		"create_directory", "read_and_move_file", "process_file", "send_file", "upload_file"} {
		if d := e.Evaluate(call(t, name, args), scope); d.Verdict != Block || d.Policy != "scope_operation" {
			t.Errorf("%s under a read scope: got %s/%s, want block/scope_operation", name, d.Verdict, d.Policy)
		}
	}
	for _, name := range []string{"read_file", "readFile", "list_directory", "search_files", "directory_tree",
		"get_file_info", "read_multiple_files"} {
		if d := e.Evaluate(call(t, name, `{"path": "/srv/data/a.txt"}`), scope); d.Policy == "scope_operation" {
			t.Errorf("%s under a read scope: blocked by scope_operation", name)
		}
	}
}

func TestResourceMatching(t *testing.T) {
	cases := []struct {
		resource, allowed string
		want              Tri
	}{
		{"/srv/finance/reports", "/srv/finance/reports", TriTrue},
		{"/srv/finance/reports/q4.pdf", "/srv/finance/reports/", TriTrue},
		{"reports", "/srv/finance/reports", TriTrue},
		{"finance/reports", "/srv/finance/reports", TriTrue},
		{"orders_2024", "orders", TriTrue},
		{"sales", "sales_2024", TriTrue},
		{"logs", "/app/logs", TriTrue},
		{"/srv/finance", "/srv/finance/reports", TriFalse},
		{"/srv", "/srv/finance/reports", TriFalse},
		{"srv", "/srv/finance/reports", TriFalse},
		{"/srv/finance/reports_old", "/srv/finance/reports", TriFalse},
		{"/home/alice/notes.txt.bak", "/home/alice/notes.txt", TriFalse},
		{"/reports", "/srv/finance/reports", TriFalse},
		{"/backup/srv/finance/reports", "/srv/finance/reports", TriFalse},
		{"application_logs/x.log", "/app/", TriFalse},
		{"https://api.example.com", "https://api.example.com/v1/data", TriFalse},
		{"https://docs.company.com/api/v2", "https://docs.company.com/api", TriTrue},
		{"https://docs.company.com/api?page=2", "https://docs.company.com/api", TriTrue},
		{"s3://reports/q4/file.csv", "s3://reports/q4", TriTrue},
		{"https://api.example.com.evil.net/x", "https://api.example.com", TriFalse},
		{"https://api.example.com@evil.net/", "https://api.example.com", TriFalse},
		{"https://api.example.com:8443/x", "https://api.example.com", TriFalse},
		{"https://docs.company.com/apix", "https://docs.company.com/api", TriFalse},
		{"s3://reports-evil/x", "s3://reports", TriFalse},
	}
	for _, c := range cases {
		s := &Scope{AllowedResources: []string{c.allowed}}
		if got := s.IsResourceAllowed(c.resource); got != c.want {
			t.Errorf("IsResourceAllowed(%q) with %q: got %v, want %v", c.resource, c.allowed, got, c.want)
		}
	}
}

func TestScopeOperation(t *testing.T) {
	const url = "https://docs.company.com/api"
	e := New(nil)
	cases := []struct {
		ops, res, deny []string
		name, args     string
		authorized     bool
	}{
		{[]string{"restart_service"}, nil, nil, "restart_service", `{"service": "api"}`, true},
		{[]string{"update_config"}, nil, nil, "update_config", `{"key": "timeout", "value": "60"}`, true},
		{[]string{"update"}, nil, nil, "update_config", `{"key": "timeout", "value": "60"}`, true},
		{[]string{"read"}, []string{url}, nil, "fetch_url", `{"url": "` + url + `"}`, true},
		{[]string{"fetch"}, []string{url}, nil, "fetch_url", `{"url": "` + url + `/v2", "method": "head"}`, true},
		{[]string{"read"}, nil, nil, "run_command", `{"cmd": "df -h"}`, true},
		{[]string{"send"}, []string{"a@company.com"}, nil, "send_email",
			`{"to": "a@company.com", "body": "Portal: https://portal.company.com"}`, true},
		{[]string{"delete"}, []string{"products"}, nil, "delete_records",
			`{"table": "products", "condition": "id IN (SELECT id FROM t)"}`, true},
		{[]string{"execute_sql"}, nil, nil, "execute_sql", `{"query": "DROP TABLE users"}`, false},
		{[]string{"update"}, nil, nil, "update_records", `{"query": "UPDATE t SET a = 1"}`, false},
		{[]string{"read"}, nil, nil, "fetch_url", `{"url": "` + url + `"}`, false},
		{[]string{"read"}, []string{url}, nil, "fetch_url", `{"url": "https://docs.company.com/apix"}`, false},
		{[]string{"read"}, []string{url}, nil, "http_request", `{"url": "` + url + `", "method": "POST"}`, false},
		{[]string{"read"}, nil, nil, "run_command", `{"cmd": "df -h; cat /etc/shadow"}`, false},
		{[]string{"read"}, nil, nil, "run_command", `{"cmd": "du -sh $(cat /etc/passwd)"}`, false},
		{[]string{"read"}, nil, []string{"execute"}, "run_command", `{"cmd": "df -h"}`, false},
		{[]string{"read", "execute"}, nil, []string{"run_command"}, "run_command", `{"cmd": "ls"}`, false},
		{[]string{"send"}, nil, nil, "send_webhook", `{"url": "https://hooks.example.com/x", "text": "hi"}`, false},
		{[]string{"read"}, nil, nil, "delete_records", `{"table": "t", "condition": "id IN (SELECT id FROM t)"}`, false},
	}
	for _, c := range cases {
		scope := &Scope{Task: "t", AllowedOperations: c.ops, AllowedResources: c.res, DenyOperations: c.deny}
		d := e.Evaluate(call(t, c.name, c.args), scope)
		if got := d.Policy != "scope_operation"; got != c.authorized {
			t.Errorf("ops=%v %s %s: got %s/%s, want authorized=%v", c.ops, c.name, c.args, d.Verdict, d.Policy, c.authorized)
		}
	}
	scope := &Scope{Task: "t", AllowedOperations: []string{"execute"}}
	if d := e.Evaluate(call(t, "run_command", `{"cmd": "df -h; cat /etc/shadow"}`), scope); d.Verdict == Allow {
		t.Errorf("chained diagnostic under execute: got allow")
	}
	scope = &Scope{Task: "t", AllowedOperations: []string{"delete"}, AllowedResources: []string{"products"}}
	d := e.Evaluate(call(t, "delete_records", `{"table": "products", "condition": "id IN (SELECT id FROM t)"}`), scope)
	if d.Verdict != Escalate || d.Policy != "sql_analysis" {
		t.Errorf("delete tool with read-only SQL: got %s/%s, want escalate/sql_analysis", d.Verdict, d.Policy)
	}
}

// BenchmarkEvaluateDevSet measures the rule path over every tool call in the
// dev benchmark (466 real agent calls, mixed SQL / file / HTTP / shell / comms).
func BenchmarkEvaluateDevSet(b *testing.B) {
	type step struct {
		ToolName  string          `json:"tool_name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	type kase struct {
		Task  string `json:"task"`
		Scope Scope  `json:"scope"`
		Steps []step `json:"steps"`
	}
	f, err := os.Open("../../../bench/data/dev_set.jsonl")
	if err != nil {
		b.Skip(err)
	}
	defer f.Close()
	type item struct {
		tc    *ToolCall
		scope *Scope
	}
	var items []item
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	for sc.Scan() {
		var k kase
		if err := json.Unmarshal(sc.Bytes(), &k); err != nil {
			b.Fatal(err)
		}
		s := k.Scope
		s.Task = k.Task
		for _, st := range k.Steps {
			o, err := pyjson.ParseObject(st.Arguments)
			if err != nil {
				b.Fatal(err)
			}
			items = append(items, item{NewToolCall(st.ToolName, o), &s})
		}
	}
	e := New(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		it := items[i%len(items)]
		tc := NewToolCall(it.tc.Name, it.tc.Args) // fresh call: no cached dumps
		e.Evaluate(tc, it.scope)
	}
}
