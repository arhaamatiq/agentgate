// Package rules is AgentGate's deterministic decision path ("Tier 1").
//
// It is a line-by-line port of the Python reference engine
// (agentgate/engine.py and agentgate/analyzers/*). The parity test in this
// package replays a corpus through both implementations and requires
// identical verdicts, policy names, severities and reasoning strings, so
// the Go gateway inherits the reference engine's benchmark behavior.
//
// Evaluate never panics outward: any internal error becomes BLOCK.
package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/arhaamatiq/agentgate/gateway/internal/pyjson"
)

type Verdict string

const (
	Allow    Verdict = "allow"
	Block    Verdict = "block"
	Escalate Verdict = "escalate"
)

type Severity string

const (
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

var sevRank = map[Severity]int{SevLow: 0, SevMedium: 1, SevHigh: 2, SevCritical: 3}

func maxSeverity(a, b Severity) Severity {
	if sevRank[a] >= sevRank[b] {
		return a
	}
	return b
}

// ActionType values mirror agentgate.models.ActionType.
const (
	ActSQL     = "sql"
	ActFS      = "filesystem"
	ActHTTP    = "http"
	ActShell   = "shell"
	ActUnknown = "unknown"
)

// PolicyRuleError is the policy name for a decision forced by an internal
// rule failure (panic or malformed input the reference would crash on).
const PolicyRuleError = "rule_engine_error"

type Decision struct {
	Verdict    Verdict  `json:"verdict"`
	Tier       int      `json:"tier"`
	Policy     string   `json:"policy"`
	Severity   Severity `json:"severity"`
	Reasoning  string   `json:"reasoning"`
	ActionType string   `json:"action_type"`
	Operation  string   `json:"operation"`
}

// ToolCall is one intercepted call. Args keeps the agent's key order.
type ToolCall struct {
	Name string
	Args *pyjson.Obj

	dumps string // json.dumps(Args), computed once
}

func NewToolCall(name string, args *pyjson.Obj) *ToolCall {
	if args == nil {
		args = pyjson.NewObj()
	}
	return &ToolCall{Name: name, Args: args}
}

func (tc *ToolCall) argsDumps() string {
	if tc.dumps == "" {
		tc.dumps = pyjson.DumpsObj(tc.Args)
	}
	return tc.dumps
}

// RegisteredTool declares a tool's type explicitly (register_tools).
type RegisteredTool struct {
	ActionType  string `json:"action_type" yaml:"action_type"`
	ResourceKey string `json:"resource_key" yaml:"resource_key"`
}

type Engine struct {
	Registry map[string]RegisteredTool
}

func New(registry map[string]RegisteredTool) *Engine {
	if registry == nil {
		registry = map[string]RegisteredTool{}
	}
	return &Engine{Registry: registry}
}

// testHook lets tests inject a fault inside evaluation.
var testHook func(*ToolCall)

// ruleError aborts evaluation where the Python reference would raise.
type ruleError struct{ msg string }

// Evaluate runs the deterministic path. scope == nil means no scope declared.
func (e *Engine) Evaluate(tc *ToolCall, scope *Scope) (d Decision) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprint(r)
			if re, ok := r.(ruleError); ok {
				msg = re.msg
			}
			d = Decision{
				Verdict: Block, Tier: 1, Policy: PolicyRuleError, Severity: SevHigh,
				Reasoning: "Rule evaluation failed (" + msg + ") — blocking by default (fail-closed)",
			}
		}
	}()
	if testHook != nil {
		testHook(tc)
	}
	at := e.classify(tc)
	d = e.evaluate(tc, scope, at)
	d.Tier = 1
	d.ActionType = at
	if d.Operation == "" {
		d.Operation = e.operation(at, tc, scope)
	}
	return d
}

func (e *Engine) evaluate(tc *ToolCall, scope *Scope, at string) Decision {
	validated := false
	if scope != nil {
		if d, ok := e.checkScope(tc, scope, at); ok {
			return d
		}
		validated = true
	}
	return e.staticAnalysis(tc, scope, at, validated)
}

var registeredTypeToAction = map[string]string{
	"database": ActSQL, "read": ActFS, "write": ActFS, "communication": ActUnknown,
	"config": ActUnknown, "deploy": ActUnknown, "export": ActUnknown, "execute": ActShell,
}

var registeredTypeToOperation = map[string]string{
	"database": "database", "read": "read", "write": "write", "delete": "delete",
	"communication": "send", "config": "config", "deploy": "deploy", "export": "export", "execute": "execute",
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

var (
	sqlInArgs = mustRe(`(?i)\b(?:SELECT` + reS + `+` + reNotS + `+` + reS + `+FROM\b|INSERT` + reS + `+INTO\b|UPDATE` + reS + `+` + reNotS + `+` + reS + `+SET\b` +
		`|DELETE` + reS + `+FROM\b|DROP` + reS + `+(?:TABLE|DATABASE|INDEX|VIEW)\b` +
		`|TRUNCATE` + reS + `+(?:TABLE` + reS + `+)?` + reW + `|CREATE` + reS + `+(?:TABLE|INDEX|VIEW)\b` +
		`|ALTER` + reS + `+TABLE\b|GRANT` + reS + `+` + reW + `|REVOKE` + reS + `+` + reW +
		`|REFRESH` + reS + `+MATERIALIZED)`)
	shellPrefix   = mustRe(`\A(?:run_command|execute_command|exec_)`)
	sqlDestructWB = mustRe(`(?i)\b(?:DROP|TRUNCATE|DELETE` + reS + `+FROM|ALTER` + reS + `+TABLE|GRANT|REVOKE)\b`)
	sqlWriteWB    = mustRe(`(?i)\b(?:INSERT|UPDATE|CREATE|MERGE|UPSERT|REPLACE|REFRESH)\b`)
)

// classify mirrors _classify_action.
func (e *Engine) classify(tc *ToolCall) string {
	name := tc.Name
	nl := pyLower(name)
	if reg, ok := e.Registry[name]; ok {
		if at, ok := registeredTypeToAction[reg.ActionType]; ok {
			return at
		}
	}
	switch {
	case containsAny(nl, "sql", "query", "database", "db"):
		return ActSQL
	case containsAny(nl, "file", "read_file", "write_file", "path", "fs", "directory"):
		return ActFS
	case containsAny(nl, "http", "request", "fetch", "curl", "api_call", "url"):
		return ActHTTP
	case containsAny(nl, "shell", "bash", "terminal"):
		return ActShell
	}
	argsLower := pyLower(tc.argsDumps())
	// json.dumps output is pure ASCII, so RE2's ASCII \b is exact here.
	if sqlInArgs.MatchString(argsLower) {
		return ActSQL
	}
	if containsAny(argsLower, "http://", "https://", "ftp://") {
		// A link in a message is content, not a request (see _classify_action).
		_, hasURL := tc.Args.Get("url")
		_, hasEndpoint := tc.Args.Get("endpoint")
		if !sendName(nl) || hasURL || hasEndpoint {
			return ActHTTP
		}
	}
	if shellPrefix.MatchString(nl) {
		return ActShell
	}
	return ActUnknown
}

type opPattern struct {
	match func(string) bool
	op    string
}

func prefixes(ps ...string) func(string) bool {
	return func(s string) bool {
		for _, p := range ps {
			if strings.HasPrefix(s, p) {
				return true
			}
		}
		return false
	}
}

var defaultOperationPatterns = []opPattern{
	{prefixes("read_", "get_", "list_", "describe_", "show_", "fetch_", "check_"), "read"},
	{func(s string) bool {
		// ^write_|^save_|^put_|^create_(?!.*command)
		if prefixes("write_", "save_", "put_")(s) {
			return true
		}
		return strings.HasPrefix(s, "create_") && !strings.Contains(strings.SplitN(s[len("create_"):], "\n", 2)[0], "command")
	}, "write"},
	{prefixes("delete_", "remove_", "purge_", "clear_"), "delete"},
	{prefixes("send_", "forward_", "notify_", "post_message", "broadcast_"), "send"},
	{prefixes("execute_sql", "run_query", "query_"), "database"},
	{prefixes("update_config", "set_config", "configure_"), "config"},
	{prefixes("deploy_", "rollout_", "release_", "restart_", "start_", "stop_"), "deploy"},
	{prefixes("export_", "sync_", "push_", "upload_", "transfer_"), "export"},
	{prefixes("run_command", "execute_command", "shell_", "exec_"), "execute"},
	{prefixes("run_"), "execute"},
}

// A filesystem tool is a read only if a word of its name is a read word and
// none is a mutating one; anything else is a write (see _FS_READ_WORDS).
var fsReadWords = wordSet("read", "list", "get", "describe", "fetch", "show", "check", "inspect", "monitor",
	"tail", "search", "find", "view", "stat", "cat", "head", "glob", "exists", "count",
	"info", "tree")

var fsMutatingWords = wordSet("create", "edit", "move", "rename", "append", "copy", "update", "modify", "overwrite",
	"truncate", "mkdir", "rmdir", "chmod", "chown", "touch", "patch", "replace", "insert",
	"put", "set", "add", "make", "empty", "purge", "clear", "restore", "extract", "unzip",
	"mv", "cp", "rm", "ln", "link", "symlink")

func wordSet(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func isLowerOrDigit(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }

// nameWords mirrors _name_words: split camelCase, lower-case, split on
// anything outside [a-z0-9].
func nameWords(name string) []string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if i > 0 && isLowerOrDigit(name[i-1]) && name[i] >= 'A' && name[i] <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteByte(name[i])
	}
	return strings.FieldsFunc(pyLower(b.String()), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

func anyWord(words []string, set map[string]bool) bool {
	for _, w := range words {
		if set[w] {
			return true
		}
	}
	return false
}

var sendName = prefixes("send_", "forward_", "notify_", "post_message", "broadcast_")

// sqlArgsOperation mirrors _sql_args_operation.
func sqlArgsOperation(tc *ToolCall) string {
	args := tc.argsDumps()
	if sqlDestructWB.MatchString(args) {
		return "destructive"
	}
	if sqlWriteWB.MatchString(args) {
		return "write"
	}
	return "read"
}

// nameChangesData mirrors _name_changes_data.
func nameChangesData(nl string) string {
	for _, p := range defaultOperationPatterns {
		if (p.op == "write" || p.op == "delete") && p.match(nl) {
			return p.op
		}
	}
	return ""
}

// readsOnly mirrors _reads_only: a plain diagnostic command, or a GET/HEAD
// to a URL the scope's resources explicitly grant.
func readsOnly(tc *ToolCall, at string, s *Scope) bool {
	switch at {
	case ActShell:
		return isPlainDiagnostic(shellCommand(tc))
	case ActHTTP:
		if m, ok := tc.Args.Get("method"); ok && m.Kind != pyjson.Null {
			if m.Kind != pyjson.String {
				return false
			}
			if l := pyLower(pyStrip(m.S)); l != "get" && l != "head" {
				return false
			}
		}
		u, ok := tc.Args.Get("url")
		if !ok || !u.Truthy() {
			u, ok = tc.Args.Get("endpoint")
		}
		return ok && u.Kind == pyjson.String && u.S != "" && s.IsResourceAllowed(u.S) == TriTrue
	}
	return false
}

// operation mirrors PolicyEngine._operation: the inferred class, or "read"
// for a call that only reads when the scope grants reading but not the class.
func (e *Engine) operation(at string, tc *ToolCall, s *Scope) string {
	op := e.mapOperation(at, tc)
	if s != nil && (op == "execute" || op == "http") && !contains(s.DenyOperations, op) &&
		s.IsOperationAllowed(op, tc.Name) == TriFalse && s.IsOperationAllowed("read", tc.Name) == TriTrue &&
		readsOnly(tc, at, s) {
		return "read"
	}
	return op
}

// mapOperation mirrors _map_operation.
func (e *Engine) mapOperation(at string, tc *ToolCall) string {
	nl := pyLower(tc.Name)
	if reg, ok := e.Registry[tc.Name]; ok {
		if op, ok := registeredTypeToOperation[reg.ActionType]; ok {
			return op
		}
	}
	switch at {
	case ActSQL:
		// delete_records(condition="id IN (SELECT ...)") is not a read.
		if op := sqlArgsOperation(tc); op != "read" {
			return op
		}
		if op := nameChangesData(nl); op != "" {
			return op
		}
		return "read"
	case ActFS:
		if containsAny(nl, "write", "save", "delete", "remove") {
			return "write"
		}
		// send_file, upload_file: the recipient and destination checks apply.
		for _, p := range defaultOperationPatterns {
			if (p.op == "send" || p.op == "export") && p.match(nl) {
				return p.op
			}
		}
		if w := nameWords(tc.Name); anyWord(w, fsReadWords) && !anyWord(w, fsMutatingWords) {
			return "read"
		}
		return "write"
	case ActHTTP:
		return "http"
	case ActShell:
		return "execute"
	}
	for _, p := range defaultOperationPatterns {
		if p.match(nl) {
			return p.op
		}
	}
	return "unknown"
}

func reprStr(s string) string             { return pyjson.Repr(s) }
func pyReprStrList(items []string) string { return pyjson.ReprList(items) }

func listRepr(items []string) string {
	if items == nil {
		items = []string{}
	}
	return pyjson.ReprList(items)
}

func dec(v Verdict, policy string, sev Severity, reasoning string) Decision {
	return Decision{Verdict: v, Policy: policy, Severity: sev, Reasoning: reasoning}
}

var (
	credentialService = mustRe(`(?i)\A(?:credentials|secrets|passwd|shadow|authorized_keys)` + reEnd)
	credentialDot     = mustRe(`(?i)\A\.(?:env|pem|key|ssh|aws|pgpass)`)
	massAudience      = mustRe(`(?i)\b(?:all_users|all_customers|everyone|customer_base|all_employees|all_subscribers|all_contacts|entire_|broadcast)\b`)
	sensitiveFields   = mustRe(`(?i)\b(?:password|password_hash|passwd|secret|api_key|api_secret|access_token|refresh_token|private_key|signing_key|credential|auth_token|session_token|bearer|ssn|social_security|credit_card|card_number|cvv|encryption_key|master_key|client_secret)\b`)
	infraRedFlag      = mustRe(`(?i)(?:security[._]group|firewall|[._]permissions?\b|[._]roles?\b|load_balancer|ssl|tls|certificate|iam|acl|auth[z]?[._]|rbac|network[._]policy|ingress|egress|default_role|superuser|admin_level|privilege|secret|api[_-]?key|token[_.]rotation)`)
)

func credentialInService(svc string) bool {
	if strings.Contains(svc, "/") || credentialService.MatchString(svc) {
		return true
	}
	if loc := credentialDot.FindStringIndex(svc); loc != nil {
		return wordEndsAt(svc, loc[1])
	}
	return false
}

// argStr returns str(args[key]) and whether key is present.
func argStr(o *pyjson.Obj, key string) (string, bool) {
	v, ok := o.Get(key)
	if !ok {
		return "", false
	}
	return v.PyStr(), true
}

// argGetStr mirrors `args.get(key, "")` used where the value then has string
// methods called on it: a truthy non-string would raise in Python.
func argGetStr(o *pyjson.Obj, key string) (s string, truthy bool) {
	v, ok := o.Get(key)
	if !ok || !v.Truthy() {
		return "", false
	}
	if v.Kind != pyjson.String {
		panic(ruleError{fmt.Sprintf("argument %q is not a string", key)})
	}
	return v.S, true
}

func (e *Engine) checkScope(tc *ToolCall, s *Scope, at string) (Decision, bool) {
	op := e.operation(at, tc, s)
	args := tc.Args
	if op == "unknown" {
		return dec(Escalate, "scope_unknown_operation", SevMedium,
			fmt.Sprintf("Cannot determine operation type for tool '%s' — escalating to Tier 2", tc.Name)), true
	}
	if s.IsOperationAllowed(op, tc.Name) == TriFalse {
		return dec(Block, "scope_operation", SevHigh,
			fmt.Sprintf("Operation '%s' not in allowed operations: %s", op, listRepr(s.AllowedOperations))), true
	}
	for _, key := range []string{"resource", "path", "table", "database", "file", "url"} {
		res, ok := argStr(args, key)
		if !ok {
			continue
		}
		if key == "path" || key == "file" {
			if t := pyStrip(res); t == "/" || t == "." || t == "./" {
				if len(s.AllowedResources) > 0 {
					return dec(Block, "scope_root_path", SevHigh,
						fmt.Sprintf("Root/unrestricted path '%s' not authorized when scope declares specific resources: %s",
							res, listRepr(s.AllowedResources))), true
				}
			}
		}
		if s.IsResourceAllowed(res) == TriFalse {
			return dec(Block, "scope_resource", SevHigh,
				fmt.Sprintf("Resource '%s' not in allowed resources: %s", res, listRepr(s.AllowedResources))), true
		}
	}
	if svc, ok := argStr(args, "service"); ok && credentialInService(svc) {
		return dec(Escalate, "credential_service_name", SevHigh,
			fmt.Sprintf("Service argument '%s' appears to target credential/config files rather than actual services — escalating to Tier 2", svc)), true
	}
	if op != "read" && op != "database" {
		if svc, ok := argStr(args, "service"); ok && len(s.AllowedResources) > 0 {
			if s.IsResourceAllowed(svc) == TriFalse && !s.isSQLTableRelated(svc) {
				return dec(Escalate, "scope_service_resource", SevHigh,
					fmt.Sprintf("Service '%s' not in allowed resources %s — escalating to Tier 2", svc, listRepr(s.AllowedResources))), true
			}
		}
	}
	if dest, ok := argStr(args, "destination"); ok && len(s.AllowedResources) > 0 {
		if s.IsResourceAllowed(dest) == TriFalse {
			return dec(Escalate, "scope_export_destination", SevMedium,
				fmt.Sprintf("Export destination '%s' not in allowed resources — escalating to Tier 2", dest)), true
		}
	}
	if len(s.AllowedResources) > 0 {
		if d, ok := e.checkSQLResources(tc, s); ok {
			return d, true
		}
	}
	switch op {
	case "send":
		return e.checkCommunication(tc, s)
	case "export":
		if v, ok := args.Get("destination"); ok && v.Truthy() && len(s.AllowedResources) > 0 {
			dest, _ := argGetStr(args, "destination")
			if s.IsResourceAllowed(dest) == TriFalse {
				return dec(Escalate, "scope_export_destination", SevHigh,
					fmt.Sprintf("Export destination '%s' not in allowed resources — escalating to Tier 2", dest)), true
			}
		}
	case "config":
		if key, truthy := argGetStr(args, "key"); truthy && infraRedFlag.MatchString(key) {
			return dec(Escalate, "infra_red_flag", SevHigh,
				fmt.Sprintf("Config change touches security-sensitive key '%s' — escalating to Tier 2", key)), true
		}
	}
	return Decision{}, false
}

func (e *Engine) checkSQLResources(tc *ToolCall, s *Scope) (Decision, bool) {
	query, truthy := argGetStr(tc.Args, "query")
	if !truthy {
		return Decision{}, false
	}
	tables := extractTables(query)
	var unmatched []string
	for _, t := range tables {
		if s.IsResourceAllowed(t) != TriFalse || s.isSQLTableRelated(t) {
			continue
		}
		unmatched = append(unmatched, t)
	}
	if len(unmatched) > 0 {
		return dec(Escalate, "scope_sql_resource", SevMedium,
			fmt.Sprintf("SQL table(s) %s not clearly related to allowed resources %s — escalating to Tier 2",
				listRepr(unmatched), listRepr(s.AllowedResources))), true
	}
	return Decision{}, false
}

func (e *Engine) checkCommunication(tc *ToolCall, s *Scope) (Decision, bool) {
	for _, key := range []string{"to", "channel", "recipient", "recipients", "audience"} {
		rcpt, ok := argStr(tc.Args, key)
		if !ok {
			continue
		}
		if pySearch(massAudience, rcpt, true, true) != nil {
			if len(s.AllowedResources) > 0 && s.IsResourceAllowed(rcpt) == TriFalse {
				return dec(Block, "scope_mass_communication", SevHigh,
					fmt.Sprintf("Mass communication to '%s' not in allowed resources: %s", rcpt, listRepr(s.AllowedResources))), true
			}
		}
		if len(s.AllowedResources) > 0 && s.IsResourceAllowed(rcpt) == TriFalse {
			return dec(Escalate, "scope_recipient", SevMedium,
				fmt.Sprintf("Recipient '%s' not in allowed resources — escalating to Tier 2", rcpt)), true
		}
	}
	for _, key := range []string{"body", "message", "content", "text"} {
		body, ok := argStr(tc.Args, key)
		if ok && pySearch(sensitiveFields, body, true, true) != nil {
			return dec(Escalate, "sensitive_data_in_communication", SevHigh,
				"Communication body contains potentially sensitive field names (credentials, keys, tokens)"), true
		}
	}
	return Decision{}, false
}

func (e *Engine) staticAnalysis(tc *ToolCall, scope *Scope, at string, validated bool) Decision {
	switch at {
	case ActSQL:
		q, _ := argGetStr(tc.Args, "query")
		a := analyzeSQL(q)
		if a.verdict == Allow && sqlArgsOperation(tc) == "read" {
			// The analyzer saw only a read; the tool's name says it changes data.
			if changes := nameChangesData(pyLower(tc.Name)); changes != "" {
				return dec(Escalate, "sql_analysis", SevMedium, fmt.Sprintf(
					"The SQL in the arguments only reads, but tool '%s' changes data (%s) — escalating to Tier 2", tc.Name, changes))
			}
		}
		return dec(a.verdict, "sql_analysis", a.severity, a.reasoning)
	case ActFS:
		path, _ := argGetStr(tc.Args, "path")
		if path == "" {
			path, _ = argGetStr(tc.Args, "file")
		}
		if path == "" {
			path, _ = argGetStr(tc.Args, "filename")
		}
		op := "read"
		if v, ok := tc.Args.Get("operation"); ok {
			if v.Kind == pyjson.String {
				op = v.S
			} else {
				op = "\x00non-string"
			}
		}
		nl := pyLower(tc.Name)
		if containsAny(nl, "delete", "remove") {
			op = "delete"
		} else if containsAny(nl, "write", "save") {
			op = "write"
		}
		var granted []string
		if scope != nil {
			granted = scope.AllowedResources
		}
		a := analyzeFilesystem(path, op, granted)
		return dec(a.verdict, "filesystem_analysis", a.severity, a.reasoning)
	case ActHTTP:
		url, _ := argGetStr(tc.Args, "url")
		if url == "" {
			url, _ = argGetStr(tc.Args, "endpoint")
		}
		a := analyzeHTTP(url)
		return dec(a.verdict, "http_analysis", a.severity, a.reasoning)
	case ActShell:
		return e.analyzeShell(tc, validated)
	}
	if validated {
		op := e.operation(at, tc, scope)
		if op == "read" {
			return dec(Allow, "scope_validated_pass", SevLow,
				fmt.Sprintf("Tool '%s' (operation: %s) passed all scope checks", tc.Name, op))
		}
		return dec(Escalate, "scope_validated_non_read", SevMedium,
			fmt.Sprintf("Tool '%s' (operation: %s) passed scope checks but non-read operations require Tier 2 review", tc.Name, op))
	}
	return dec(Escalate, "unknown_action", SevLow,
		fmt.Sprintf("Unknown action type for tool '%s' — escalating", tc.Name))
}

var safeDiagnostic = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, a := range []string{"df", "du", "pwd", "whoami", "hostname", "uptime", "free",
		"nslookup", "dig", "ping", "traceroute", "date", "uname", "id",
		`systemctl` + reS + `+status`, "journalctl", `service` + reS + `+` + reNotS + `+` + reS + `+status`} {
		out = append(out, mustRe(`(?i)\A`+reS+`*`+a))
	}
	return out
}()

var highRiskShell = mustRe(`(?i)(?:\A|` + reS + `|;|&&|\|\|)(?:` +
	`sudo` + reS + `+|pkill` + reS + `|kill` + reS + `|killall` + reS +
	`|chmod` + reS + `|chown` + reS + `|chgrp` + reS +
	`|systemctl` + reS + `+(?:restart|stop|disable|enable)` + reS +
	`|service` + reS + `+` + reNotS + `+` + reS + `+(?:restart|stop)` +
	`|rm` + reS + `+-r|rmdir` + reS +
	`|mkfs[` + pyWS + `.]|dd` + reS + `+if=` +
	`|iptables` + reS + `|nft` + reS +
	`|reboot|shutdown|poweroff|halt` +
	`|apt-get` + reS + `+(?:install|remove|purge)` +
	`|yum` + reS + `+(?:install|remove|erase)` +
	`|pip` + reS + `+install` +
	`|flush_cache|redis-cli` + reS + `+flushall` +
	`)|>` + reS + `*/tmp/|>` + reS + `*/dev/shm/`)

// HighRiskShell reports _HIGH_RISK_SHELL_RE.search(cmd).
func HighRiskShell(cmd string) bool { return highRiskShell.MatchString(cmd) }

func isSafeDiagnostic(cmd string) bool {
	for _, re := range safeDiagnostic {
		if loc := re.FindStringIndex(cmd); loc != nil && wordEndsAt(cmd, loc[1]) {
			return true
		}
	}
	return false
}

// shellCommand mirrors _shell_command:
// str(args.get("cmd", "") or args.get("command", "") or args.get("args", "")).
func shellCommand(tc *ToolCall) string {
	cmdV := pyjson.Str("")
	for i, k := range []string{"cmd", "command", "args"} {
		v, ok := tc.Args.Get(k)
		if !ok {
			v = pyjson.Str("")
		}
		cmdV = v
		if v.Truthy() || i == 2 {
			break
		}
	}
	return cmdV.PyStr()
}

// isPlainDiagnostic mirrors _is_plain_diagnostic: a safe diagnostic that is
// the whole command line, nothing chained, piped, substituted or redirected.
func isPlainDiagnostic(cmd string) bool {
	return isSafeDiagnostic(cmd) && !strings.ContainsAny(cmd, ";|&`$()<>\n\r")
}

func (e *Engine) analyzeShell(tc *ToolCall, validated bool) Decision {
	cmd := shellCommand(tc)
	if cmd != "" && validated && isPlainDiagnostic(cmd) {
		return dec(Allow, "safe_diagnostic_command", SevLow, "Safe read-only diagnostic command within authorised scope")
	}
	if cmd != "" && HighRiskShell(cmd) {
		return dec(Escalate, "shell_high_risk", SevHigh,
			fmt.Sprintf("HIGH_RISK shell command '%s' — requires explicit scope authorization for system-level operations", runePrefix(cmd, 80)))
	}
	return dec(Escalate, "shell_always_escalate", SevMedium, "Shell command escalated to Tier 2 for review")
}
