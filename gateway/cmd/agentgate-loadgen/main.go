// agentgate-loadgen: latency/throughput benchmark for the gateway.
//
// Payloads are the real tool calls from the dev benchmark set. A probe pass
// keeps only calls the deterministic rule path decides (tier 1), so the run
// measures the rule path rather than LLM latency.
//
// Open-loop mode sends at a fixed rate and measures each request from its
// *scheduled* send time, so a stalled server shows up as latency instead of
// silently lowering the offered load (no coordinated omission).
// Closed-loop mode runs N workers back to back to find maximum throughput.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type payload struct {
	body []byte
}

type sample struct {
	latency  time.Duration
	serverUS int64
	ok       bool
	verdict  string
}

type Summary struct {
	Mode          string             `json:"mode"`
	TargetRPS     int                `json:"target_rps,omitempty"`
	Concurrency   int                `json:"concurrency,omitempty"`
	DurationS     float64            `json:"duration_s"`
	Requests      int                `json:"requests"`
	Errors        int                `json:"errors"`
	AchievedRPS   float64            `json:"achieved_rps"`
	LatencyMS     map[string]float64 `json:"latency_ms"`
	ServerMS      map[string]float64 `json:"server_decision_ms"`
	Verdicts      map[string]int     `json:"verdicts"`
	PayloadPool   int                `json:"payload_pool"`
	URL           string             `json:"url"`
	ClientCPUs    int                `json:"client_cpus"`
	StartedAt     string             `json:"started_at"`
	GoVersion     string             `json:"go_version"`
	ProbeSkipped  int                `json:"probe_excluded_tier2"`
	WarmupSeconds float64            `json:"warmup_s"`
}

func main() {
	url := flag.String("url", "http://localhost:8080/v1/check", "gateway check endpoint")
	dataset := flag.String("dataset", "bench/data/dev_set.jsonl", "JSONL benchmark set to draw tool calls from")
	mode := flag.String("mode", "open", "open (fixed rate) or closed (max throughput)")
	rate := flag.Int("rate", 1000, "requests per second (open mode)")
	conc := flag.Int("concurrency", 64, "workers (closed mode) / max in-flight (open mode)")
	dur := flag.Duration("duration", 30*time.Second, "measured duration")
	warm := flag.Duration("warmup", 5*time.Second, "unmeasured warmup at the same load")
	out := flag.String("out", "", "write JSON summary here")
	flag.Parse()

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		MaxIdleConns: 4096, MaxIdleConnsPerHost: 4096, IdleConnTimeout: 90 * time.Second,
	}}
	pool, skipped := buildPool(client, *url, *dataset)
	fmt.Fprintf(os.Stderr, "payload pool: %d tier-1 calls (%d escalating calls excluded)\n", len(pool), skipped)

	var s *Summary
	switch *mode {
	case "open":
		run(client, *url, pool, *rate, *conc, *warm, false)
		s = run(client, *url, pool, *rate, *conc, *dur, true)
		s.Mode, s.TargetRPS = "open", *rate
	case "closed":
		closed(client, *url, pool, *conc, *warm)
		s = closed(client, *url, pool, *conc, *dur)
		s.Mode = "closed"
	default:
		fmt.Fprintln(os.Stderr, "mode must be open or closed")
		os.Exit(2)
	}
	s.Concurrency, s.PayloadPool, s.URL, s.ClientCPUs = *conc, len(pool), *url, runtime.NumCPU()
	s.GoVersion, s.ProbeSkipped, s.WarmupSeconds = runtime.Version(), skipped, warm.Seconds()
	b, _ := json.MarshalIndent(s, "", "  ")
	fmt.Println(string(b))
	if *out != "" {
		_ = os.WriteFile(*out, append(b, '\n'), 0o644)
	}
}

func buildPool(client *http.Client, url, dataset string) ([]payload, int) {
	f, err := os.Open(dataset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	var pool []payload
	skipped := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	n := 0
	for sc.Scan() {
		var c struct {
			CaseID string          `json:"case_id"`
			Task   string          `json:"task"`
			Scope  json.RawMessage `json:"scope"`
			Steps  []struct {
				ToolName  string          `json:"tool_name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"steps"`
		}
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			continue
		}
		var scope map[string]any
		_ = json.Unmarshal(c.Scope, &scope)
		scope["task"] = c.Task
		for _, st := range c.Steps {
			n++
			body, _ := json.Marshal(map[string]any{
				"agent_id": "loadgen", "session_id": fmt.Sprintf("loadgen-%d", n%512), "task": c.Task,
				"scope": scope, "tool_name": st.ToolName, "arguments": st.Arguments,
			})
			if s := do(client, url, body, time.Now()); s.ok && tierOf(s) == 1 {
				pool = append(pool, payload{body})
			} else {
				skipped++
			}
		}
	}
	if len(pool) == 0 {
		fmt.Fprintln(os.Stderr, "no tier-1 payloads: is the gateway running with allow_inline_scope?")
		os.Exit(1)
	}
	return pool, skipped
}

var lastTier atomic.Int64

func tierOf(sample) int { return int(lastTier.Load()) }

func do(client *http.Client, url string, body []byte, scheduled time.Time) sample {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return sample{latency: time.Since(scheduled)}
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	lat := time.Since(scheduled)
	var r struct {
		Verdict string `json:"verdict"`
		Tier    int    `json:"tier"`
	}
	_ = json.Unmarshal(b, &r)
	lastTier.Store(int64(r.Tier))
	us, _ := strconv.ParseInt(resp.Header.Get("X-AgentGate-Decision-Us"), 10, 64)
	return sample{latency: lat, serverUS: us, ok: resp.StatusCode == 200 && r.Verdict != "", verdict: r.Verdict}
}

func run(client *http.Client, url string, pool []payload, rate, maxInflight int, dur time.Duration, measure bool) *Summary {
	interval := time.Second / time.Duration(rate)
	total := int(dur / interval)
	samples := make([]sample, total)
	sem := make(chan struct{}, maxInflight*16)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < total; i++ {
		scheduled := start.Add(time.Duration(i) * interval)
		if d := time.Until(scheduled); d > 0 {
			time.Sleep(d)
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, scheduled time.Time) {
			defer wg.Done()
			samples[i] = do(client, url, pool[i%len(pool)].body, scheduled)
			<-sem
		}(i, scheduled)
	}
	wg.Wait()
	elapsed := time.Since(start)
	return summarize(samples, elapsed)
}

func closed(client *http.Client, url string, pool []payload, workers int, dur time.Duration) *Summary {
	var mu sync.Mutex
	var samples []sample
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	start := time.Now()
	var seq atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]sample, 0, 4096)
			for ctx.Err() == nil {
				i := seq.Add(1)
				local = append(local, do(client, url, pool[int(i)%len(pool)].body, time.Now()))
			}
			mu.Lock()
			samples = append(samples, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return summarize(samples, time.Since(start))
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func summarize(samples []sample, elapsed time.Duration) *Summary {
	var lat, srv []float64
	s := &Summary{Verdicts: map[string]int{}, StartedAt: time.Now().Add(-elapsed).UTC().Format(time.RFC3339)}
	for _, x := range samples {
		s.Requests++
		if !x.ok {
			s.Errors++
			continue
		}
		s.Verdicts[x.verdict]++
		lat = append(lat, float64(x.latency.Microseconds())/1000)
		srv = append(srv, float64(x.serverUS)/1000)
	}
	sort.Float64s(lat)
	sort.Float64s(srv)
	q := func(v []float64) map[string]float64 {
		return map[string]float64{"p50": pct(v, .50), "p90": pct(v, .90), "p99": pct(v, .99), "p99.9": pct(v, .999), "max": pct(v, 1)}
	}
	s.LatencyMS, s.ServerMS = q(lat), q(srv)
	s.DurationS = elapsed.Seconds()
	s.AchievedRPS = float64(s.Requests-s.Errors) / elapsed.Seconds()
	return s
}
