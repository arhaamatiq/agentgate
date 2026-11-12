package gateway

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Registry        *prometheus.Registry
	Decisions       *prometheus.CounterVec
	DecisionLatency *prometheus.HistogramVec
	FailClosed      *prometheus.CounterVec
	JudgeCalls      *prometheus.CounterVec
	JudgeLatency    prometheus.Histogram
	JudgeCache      *prometheus.CounterVec
	AuditFailures   prometheus.Counter
}

func NewMetrics() *Metrics {
	r := prometheus.NewRegistry()
	m := &Metrics{
		Registry: r,
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "agentgate_decisions_total", Help: "Decisions by verdict, tier and policy.",
		}, []string{"verdict", "tier", "policy"}),
		DecisionLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "agentgate_decision_seconds", Help: "Decision latency inside the gateway.",
			Buckets: []float64{.0001, .00025, .0005, .001, .002, .005, .01, .05, .25, 1, 2.5, 5, 10},
		}, []string{"tier"}),
		FailClosed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "agentgate_fail_closed_total", Help: "Calls blocked because a component failed.",
		}, []string{"reason"}),
		JudgeCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "agentgate_judge_calls_total", Help: "Tier 2 judge calls by outcome.",
		}, []string{"outcome"}),
		JudgeLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "agentgate_judge_seconds", Help: "Tier 2 judge round trip.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 10),
		}),
		JudgeCache: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "agentgate_judge_cache_total", Help: "Judge verdict cache lookups.",
		}, []string{"result"}),
		AuditFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agentgate_audit_rejected_total", Help: "Decisions the audit pipeline could not accept.",
		}),
	}
	r.MustRegister(m.Decisions, m.DecisionLatency, m.FailClosed, m.JudgeCalls, m.JudgeLatency, m.JudgeCache,
		m.AuditFailures, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}
