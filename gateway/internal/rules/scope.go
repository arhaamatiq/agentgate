package rules

import (
	"strings"
	"unicode/utf8"
)

// Scope is what an agent is allowed to do (agentgate.models.ScopePolicy).
type Scope struct {
	Task              string   `json:"task" yaml:"task"`
	AllowedOperations []string `json:"allowed_operations" yaml:"allowed_operations"`
	AllowedResources  []string `json:"allowed_resources" yaml:"allowed_resources"`
	DenyOperations    []string `json:"deny_operations" yaml:"deny_operations"`
	MaxRate           int      `json:"max_rate,omitempty" yaml:"max_rate"`
}

// Tri is a Python bool | None.
type Tri int8

const (
	TriNone Tri = iota
	TriTrue
	TriFalse
)

// Subsumption: a broad operation implies narrower ones.
var Subsumption = map[string][]string{
	"write":       {"config", "send", "export", "update", "notify", "forward", "broadcast", "post"},
	"execute":     {"deploy", "restart", "run", "start", "stop", "bounce"},
	"destructive": {"delete", "purge", "drop", "truncate", "remove", "flush", "wipe"},
	"read":        {"list", "get", "describe", "fetch", "check", "show", "monitor", "tail", "inspect"},
	"send":        {"notify", "forward", "broadcast", "post"},
	"deploy":      {"restart", "bounce", "rollout", "release"},
}

// VerbOperations: a declared verb authorizes a tool whose name starts with it,
// but only if the engine's class for the call is one the verb belongs to
// (agentgate.models.VERB_OPERATIONS). So ["delete"] permits delete_file
// (class write) but not write_file, execute_sql("DROP TABLE ...") or a
// delete_* call carrying a DROP (class destructive).
var VerbOperations = func() map[string][]string {
	m := map[string][]string{}
	add := func(classes []string, verbs ...string) {
		for _, v := range verbs {
			m[v] = classes
		}
	}
	add([]string{"read"}, "list", "get", "describe", "fetch", "show", "check", "inspect",
		"monitor", "tail", "search", "find", "view")
	add([]string{"write", "delete"}, "delete", "remove", "purge", "clear")
	add([]string{"send"}, "forward", "notify", "post", "reply", "broadcast")
	add([]string{"deploy"}, "restart", "start", "stop", "rollout", "release")
	add([]string{"export", "read"}, "export", "upload")
	add([]string{"config"}, "update", "set", "configure")
	return m
}()

// ToolVerb mirrors agentgate.models.tool_verb: the leading [A-Za-z][a-z]*
// run of a tool name, lowercased (delete_file, deleteFile -> "delete").
func ToolVerb(name string) string {
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z') {
		return ""
	}
	i := 1
	for i < len(name) && name[i] >= 'a' && name[i] <= 'z' {
		i++
	}
	return strings.ToLower(name[:i])
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// IsOperationAllowed mirrors ScopePolicy.is_operation_allowed.
func (s *Scope) IsOperationAllowed(op, toolName string) Tri {
	verb := ToolVerb(toolName)
	if contains(s.DenyOperations, op) || (verb != "" && contains(s.DenyOperations, verb)) ||
		(toolName != "" && contains(s.DenyOperations, toolName)) {
		return TriFalse
	}
	if len(s.AllowedOperations) == 0 {
		return TriNone
	}
	for _, a := range s.AllowedOperations {
		if op == a || strings.HasPrefix(a, op+"_") || strings.HasPrefix(op, a+"_") || contains(Subsumption[a], op) {
			return TriTrue
		}
	}
	if contains(s.AllowedOperations, verb) && contains(VerbOperations[verb], op) {
		return TriTrue
	}
	// The scope names the tool itself; "destructive" must still be declared.
	if toolName != "" && contains(s.AllowedOperations, toolName) && op != "destructive" {
		return TriTrue
	}
	return TriFalse
}

// IsResourceAllowed mirrors ScopePolicy.is_resource_allowed.
func (s *Scope) IsResourceAllowed(resource string) Tri {
	if len(s.AllowedResources) == 0 {
		return TriNone
	}
	rn := pyStrip(strings.Trim(pyLower(resource), "/"))
	if rn == "" {
		return TriNone
	}
	rparts := strings.Split(rn, "/")
	rabs := strings.HasPrefix(pyStrip(resource), "/")
	for _, allowed := range s.AllowedResources {
		an := pyStrip(strings.Trim(pyLower(allowed), "/"))
		if an == "" {
			continue
		}
		aparts := strings.Split(an, "/")
		if rn == an || strings.HasPrefix(rn, an+"/") {
			return TriTrue
		}
		// A URL grant and a URL resource: that URL or continuing it at / ? #.
		if strings.Contains(an, "://") && strings.Contains(rn, "://") {
			if strings.HasPrefix(rn, an+"?") || strings.HasPrefix(rn, an+"#") {
				return TriTrue
			}
			continue
		}
		// An absolute path grant: itself, below it, or a bare name for its
		// last segments. Never a parent, a prefix sibling or another tail.
		if strings.HasPrefix(pyStrip(allowed), "/") {
			if !rabs && len(rparts) < len(aparts) && equalParts(rparts, aparts[len(aparts)-len(rparts):]) {
				return TriTrue
			}
			continue
		}
		if strings.HasPrefix(rn, an) {
			return TriTrue
		}
		if strings.HasPrefix(an, rn) && utf8.RuneCountInString(rn) < utf8.RuneCountInString(an) {
			if r, _ := utf8.DecodeRuneInString(an[len(rn):]); strings.ContainsRune("-_.", r) {
				return TriTrue
			}
		}
		if len(rparts) < len(aparts) && equalParts(rparts, aparts[len(aparts)-len(rparts):]) {
			return TriTrue
		}
		if len(aparts) < len(rparts) && equalParts(aparts, rparts[len(rparts)-len(aparts):]) {
			return TriTrue
		}
	}
	return TriFalse
}

func equalParts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// isSQLTableRelated mirrors PolicyEngine._is_sql_table_related.
func (s *Scope) isSQLTableRelated(table string) bool {
	tbl := pyLower(table)
	for _, allowed := range s.AllowedResources {
		a := strings.TrimLeft(pyLower(allowed), "/")
		if tbl == a || strings.HasPrefix(tbl, a+"_") || strings.HasPrefix(a, tbl+"_") {
			return true
		}
		tr, _, _ := strings.Cut(tbl, "_")
		ar, _, _ := strings.Cut(a, "_")
		if utf8.RuneCountInString(tr) >= 3 && utf8.RuneCountInString(ar) >= 3 {
			if strings.HasPrefix(tr, ar) || strings.HasPrefix(ar, tr) {
				return true
			}
		}
	}
	return false
}
