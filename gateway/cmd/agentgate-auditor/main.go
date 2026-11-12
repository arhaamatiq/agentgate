// agentgate-auditor: Kafka -> PostgreSQL writer for the hash-chained audit
// log, plus the verifier.
//
//	agentgate-auditor migrate   create schema, triggers, writer/reader roles
//	agentgate-auditor run       consume decisions and append them to the chain
//	agentgate-auditor verify    recompute every link and check signed checkpoints
//	agentgate-auditor keygen    print a new Ed25519 checkpoint signing key pair
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/arhaamatiq/agentgate/gateway/internal/audit"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentgate-auditor migrate|run|verify|keygen [flags]")
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dsn := fs.String("dsn", env("AGENTGATE_PG_DSN", ""), "PostgreSQL DSN")
	brokers := fs.String("brokers", env("AGENTGATE_KAFKA_BROKERS", ""), "Kafka brokers, comma separated")
	topic := fs.String("topic", env("AGENTGATE_AUDIT_TOPIC", "agentgate.decisions"), "decision topic")
	ckTopic := fs.String("checkpoint-topic", env("AGENTGATE_CHECKPOINT_TOPIC", "agentgate.audit.checkpoints"), "checkpoint topic")
	group := fs.String("group", env("AGENTGATE_AUDIT_GROUP", "agentgate-auditor"), "consumer group")
	signing := fs.String("signing-key", env("AGENTGATE_AUDIT_SIGNING_KEY", ""), "base64 Ed25519 seed for checkpoints")
	public := fs.String("public-key", env("AGENTGATE_AUDIT_PUBLIC_KEY", ""), "base64 Ed25519 public key (verify)")
	writerPW := fs.String("writer-password", env("AGENTGATE_PG_WRITER_PASSWORD", ""), "password for agentgate_writer (migrate)")
	readerPW := fs.String("reader-password", env("AGENTGATE_PG_READER_PASSWORD", ""), "password for agentgate_reader (migrate)")
	metricsAddr := fs.String("metrics", env("AGENTGATE_METRICS_ADDR", ":9102"), "metrics/health listen address (run)")
	asJSON := fs.Bool("json", false, "print the verification report as JSON")
	crossCheck := fs.Bool("kafka-crosscheck", false, "verify: compare every row with its source Kafka record")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}

	switch cmd {
	case "keygen":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		fmt.Printf("AGENTGATE_AUDIT_SIGNING_KEY=%s\nAGENTGATE_AUDIT_PUBLIC_KEY=%s\n",
			base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(pub))

	case "migrate":
		var err error
		for attempt := 0; attempt < 30; attempt++ { // wait for Postgres on first boot
			if err = audit.Migrate(ctx, *dsn, *writerPW, *readerPW); err == nil {
				break
			}
			slog.Warn("migrate: database not ready", "err", err)
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			fatal("migrate", err)
		}
		slog.Info("audit schema ready")

	case "run":
		cfg := audit.WriterConfig{Brokers: split(*brokers), Topic: *topic, CheckpointTopic: *ckTopic, Group: *group, DSN: *dsn}
		if *signing != "" {
			k, err := audit.ParsePrivateKey(*signing)
			if err != nil {
				fatal("signing key", err)
			}
			cfg.SigningKey = k
		} else {
			slog.Warn("no signing key: checkpoints are unsigned")
		}
		written := prometheus.NewCounter(prometheus.CounterOpts{Name: "agentgate_audit_rows_written_total", Help: "Rows appended to the chain."})
		dups := prometheus.NewCounter(prometheus.CounterOpts{Name: "agentgate_audit_duplicates_skipped_total", Help: "Redelivered events skipped."})
		reg := prometheus.NewRegistry()
		reg.MustRegister(written, dups)
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
			_ = http.ListenAndServe(*metricsAddr, mux)
		}()
		var w *audit.Writer
		var err error
		for attempt := 0; attempt < 30; attempt++ {
			if w, err = audit.NewWriter(ctx, cfg); err == nil {
				break
			}
			slog.Warn("auditor: dependencies not ready", "err", err)
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			fatal("auditor", err)
		}
		w.Written = func(n int) { written.Add(float64(n)) }
		w.Duplicates = func(n int) { dups.Add(float64(n)) }
		slog.Info("auditor running", "topic", *topic, "group", *group)
		if err := w.Run(ctx); err != nil && ctx.Err() == nil {
			fatal("auditor", err)
		}
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		w.Close(cctx)
		cancel()

	case "verify":
		cfg := audit.VerifyConfig{DSN: *dsn, Brokers: split(*brokers), CheckpointTopic: *ckTopic}
		if *crossCheck {
			cfg.CrossCheckTopic = *topic
		}
		if *public != "" {
			k, err := audit.ParsePublicKey(*public)
			if err != nil {
				fatal("public key", err)
			}
			cfg.PublicKey = k
		}
		rep, err := audit.Verify(ctx, cfg)
		if err != nil {
			fatal("verify", err)
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(rep)
		} else {
			printReport(rep)
		}
		if !rep.OK {
			os.Exit(1)
		}

	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
}

func printReport(r *audit.Report) {
	status := "INTACT"
	if !r.OK {
		status = "TAMPERING DETECTED"
	}
	fmt.Printf("audit chain: %s\n  chains: %d\n  rows verified: %d\n  rows matched to Kafka source: %d\n  signed checkpoints verified: %d (signatures checked: %v)\n  took: %d ms\n",
		status, r.Chains, r.RowsVerified, r.RowsCrossChecked, r.CheckpointsVerified, r.CheckpointsSigned, r.DurationMS)
	for _, p := range r.Problems {
		fmt.Printf("  ! chain %d seq %d: %s — %s\n", p.ChainID, p.Seq, p.Kind, p.Detail)
	}
}

func fatal(what string, err error) {
	slog.Error(what+" failed", "err", err)
	os.Exit(1)
}
