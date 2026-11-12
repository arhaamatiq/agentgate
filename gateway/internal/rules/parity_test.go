package rules

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/arhaamatiq/agentgate/gateway/internal/pyjson"
)

// TestParityWithPythonReference replays bench/parity/build_corpus.py's
// corpus. Every case was decided by the Python reference engine.
//
//   - Inputs taken from the benchmark datasets must match exactly: verdict,
//     policy, severity, reasoning, action type and operation.
//   - Fuzzed inputs must never be decided more permissively in Go. The only
//     tolerated difference is Go being stricter, which happens for a few
//     adversarial WITH statements whose sqlparse grouping Go approximates;
//     those are counted and reported.
//   - Where Python raised, Go must BLOCK.
func TestParityWithPythonReference(t *testing.T) {
	f, err := os.Open("testdata/parity.jsonl.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		Kind      string          `json:"kind"`
		ToolName  string          `json:"tool_name"`
		Arguments json.RawMessage `json:"arguments"`
		Scope     *Scope          `json:"scope"`
		Input     string          `json:"input"`
		Operation string          `json:"operation"`
		Granted   []string        `json:"granted"`
		Origin    string          `json:"origin"`
		Expect    map[string]any  `json:"expect"`
	}
	eng := New(nil)
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	counts := map[string]int{}
	var failures, stricter, sameVerdict []string
	for sc.Scan() {
		var r row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		counts[r.Kind]++
		var got map[string]any
		switch r.Kind {
		case "engine":
			args, err := pyjson.ParseObject(r.Arguments)
			if err != nil {
				t.Fatal(err)
			}
			d := eng.Evaluate(NewToolCall(r.ToolName, args), r.Scope)
			if _, raised := r.Expect["error"]; raised {
				if d.Verdict != Block || d.Policy != PolicyRuleError {
					failures = append(failures, fmt.Sprintf("engine %s %s: python raised %v, go=%s/%s", r.ToolName, r.Arguments, r.Expect["error"], d.Verdict, d.Policy))
				}
				continue
			}
			got = map[string]any{"verdict": string(d.Verdict), "policy": d.Policy, "severity": string(d.Severity),
				"reasoning": d.Reasoning, "action_type": d.ActionType, "operation": d.Operation}
		case "sql":
			a := analyzeSQL(r.Input)
			got = map[string]any{"verdict": string(a.verdict), "severity": string(a.severity), "reasoning": a.reasoning}
		case "tables":
			tables := []any{}
			for _, tb := range extractTables(r.Input) {
				tables = append(tables, tb)
			}
			got = map[string]any{"tables": tables}
		case "fs":
			a := analyzeFilesystem(r.Input, r.Operation, r.Granted)
			got = map[string]any{"verdict": string(a.verdict), "severity": string(a.severity), "reasoning": a.reasoning}
		case "http":
			a := analyzeHTTP(r.Input)
			got = map[string]any{"verdict": string(a.verdict), "severity": string(a.severity), "reasoning": a.reasoning}
		}
		if reflect.DeepEqual(got, r.Expect) {
			continue
		}
		in := r.Input
		if r.Kind == "engine" {
			sj, _ := json.Marshal(r.Scope)
			in = fmt.Sprintf("%s %s scope=%s", r.ToolName, r.Arguments, sj)
		}
		msg := fmt.Sprintf("%s[%s] %q op=%s\n   python: %v\n   go:     %v", r.Kind, r.Origin, in, r.Operation, r.Expect, got)
		if r.Origin != "dataset" {
			switch cmp := compareStrictness(r.Kind, got, r.Expect); {
			case cmp > 0:
				stricter = append(stricter, msg)
				continue
			case cmp == 0:
				sameVerdict = append(sameVerdict, msg)
				continue
			}
		}
		failures = append(failures, msg)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	t.Logf("parity cases: %d %v", total, counts)
	t.Logf("exact: %d | go stricter: %d | same verdict, different reasoning: %d | go looser or dataset mismatch: %d",
		total-len(stricter)-len(sameVerdict)-len(failures), len(stricter), len(sameVerdict), len(failures))
	if testing.Verbose() {
		for _, m := range append(stricter, sameVerdict...) {
			t.Logf("tolerated: %s", m)
		}
	}
	if len(failures) > 0 {
		show := failures
		if len(show) > 40 {
			show = show[:40]
		}
		t.Fatalf("%d/%d parity mismatches:\n%s", len(failures), total, strings.Join(show, "\n"))
	}
}

var rank = map[string]int{"allow": 0, "escalate": 1, "block": 2}

// compareStrictness returns >0 when Go is stricter than Python, 0 when the
// verdict is the same, <0 when Go is more permissive.
func compareStrictness(kind string, got, want map[string]any) int {
	if kind == "tables" {
		// Extra extracted tables mean more resources checked: stricter.
		for _, x := range want["tables"].([]any) {
			found := false
			for _, y := range got["tables"].([]any) {
				found = found || x == y
			}
			if !found {
				return -1
			}
		}
		return 1
	}
	g, _ := got["verdict"].(string)
	e, _ := want["verdict"].(string)
	return rank[g] - rank[e]
}
