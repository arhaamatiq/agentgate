// agentgate-gateway: fail-closed MCP gateway and decision API for AI agents.
//
//	agentgate-gateway serve --config policy.yaml
//	agentgate-gateway stdio --config policy.yaml --agent NAME -- <mcp server command...>
//	agentgate-gateway check --config policy.yaml --agent NAME --tool T --args '{...}'
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arhaamatiq/agentgate/gateway/internal/audit"
	"github.com/arhaamatiq/agentgate/gateway/internal/gateway"
	"github.com/arhaamatiq/agentgate/gateway/internal/judge"
	"github.com/arhaamatiq/agentgate/gateway/internal/state"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `agentgate-gateway %s

Usage:
  agentgate-gateway serve [--config FILE]
  agentgate-gateway stdio [--config FILE] --agent NAME -- COMMAND [ARGS...]
  agentgate-gateway check [--config FILE] --agent NAME --tool TOOL --args JSON
  agentgate-gateway healthcheck
  agentgate-gateway version
`, version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", os.Getenv("AGENTGATE_CONFIG"), "policy/config YAML")
	agent := fs.String("agent", "", "agent name from the policy (stdio, check)")
	tool := fs.String("tool", "", "tool name (check)")
	toolArgs := fs.String("args", "{}", "tool arguments as JSON (check)")
	switch cmd {
	case "serve", "stdio", "check":
		_ = fs.Parse(args)
	case "version":
		fmt.Println(version)
		return
	case "healthcheck":
		// For container healthchecks (the image has no shell or curl).
		port := strings.TrimPrefix(os.Getenv("AGENTGATE_LISTEN"), ":")
		if port == "" {
			port = "8080"
		}
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://127.0.0.1:" + port + "/readyz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	default:
		usage()
	}

	// In stdio mode stdout is the MCP channel: logs go to stderr regardless.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()})))
	cfg, err := gateway.LoadConfig(*configPath)
	if err != nil {
		fatal("config", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	stdio := cmd == "stdio"
	if stdio && cfg.Audit.Backend == "stdout" {
		cfg.Audit.Backend = "log"
	}
	gw, cleanup, err := build(ctx, cfg)
	if err != nil {
		fatal("startup", err)
	}
	defer cleanup()

	switch cmd {
	case "serve":
		serve(ctx, cfg, gw)
	case "stdio":
		if *agent == "" || fs.NArg() == 0 {
			usage()
		}
		if err := gw.RunStdio(ctx, *agent, fs.Args(), os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
			fatal("stdio", err)
		}
	case "check":
		res := gw.Decide(ctx, &gateway.CheckRequest{AgentID: *agent, ToolName: *tool, Arguments: json.RawMessage(*toolArgs)})
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if res.Verdict != "allow" {
			cleanup()
			os.Exit(1)
		}
	}
}

func build(ctx context.Context, cfg *gateway.Config) (*gateway.Gateway, func(), error) {
	var closers []func()
	cleanup := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	var j judge.Judge = judge.None{}
	if cfg.Judge.Address != "" {
		c, err := judge.Dial(cfg.Judge.Address, cfg.Judge.Timeout)
		if err != nil {
			return nil, cleanup, err
		}
		j = c
		closers = append(closers, func() { _ = c.Close() })
	} else {
		slog.Warn("no judge configured: escalated calls will be blocked")
	}

	var st state.Store = state.NewMemory()
	if cfg.State.Backend == "redis" {
		r, err := state.NewRedis(cfg.State.RedisURL)
		if err != nil {
			return nil, cleanup, err
		}
		st = r
		closers = append(closers, func() { _ = r.Close() })
	}

	var sink audit.Sink = audit.Discard{}
	switch cfg.Audit.Backend {
	case "kafka":
		p, err := audit.NewProducer(ctx, audit.ProducerConfig{
			Brokers: cfg.Audit.Brokers, Topic: cfg.Audit.Topic, Partitions: cfg.Audit.Partitions,
			Sync: cfg.Audit.Mode == "sync",
		})
		if err != nil {
			return nil, cleanup, err
		}
		sink = p
		closers = append(closers, func() {
			fctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := p.Close(fctx); err != nil {
				slog.Error("audit flush on shutdown failed", "err", err)
			}
			acked, failed, buffered := p.Stats()
			slog.Info("audit producer closed", "acked", acked, "failed", failed, "unflushed", buffered)
		})
	case "stdout":
		sink = audit.NewLogSink(os.Stdout)
	case "log":
		sink = audit.NewLogSink(os.Stderr)
	case "none", "":
	default:
		return nil, cleanup, fmt.Errorf("unknown audit backend %q", cfg.Audit.Backend)
	}
	return gateway.New(cfg, j, st, sink, gateway.NewMetrics()), cleanup, nil
}

func serve(ctx context.Context, cfg *gateway.Config, gw *gateway.Gateway) {
	srv := &http.Server{Addr: cfg.Listen, Handler: gw.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		slog.Info("agentgate gateway listening", "addr", cfg.Listen, "version", version,
			"judge", cfg.Judge.Address, "state", cfg.State.Backend, "audit", cfg.Audit.Backend+"/"+cfg.Audit.Mode,
			"agents", len(cfg.Agents))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("listen", err)
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down: draining requests and flushing audit log")
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}

func logLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(os.Getenv("AGENTGATE_LOG_LEVEL"))); err != nil {
		return slog.LevelInfo
	}
	return l
}

func fatal(what string, err error) {
	slog.Error(what+" failed", "err", err)
	os.Exit(1)
}
