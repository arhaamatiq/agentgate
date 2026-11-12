package gateway

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/arhaamatiq/agentgate/gateway/internal/rules"
)

type Config struct {
	Listen    string `yaml:"listen"`
	GatewayID string `yaml:"gateway_id"`

	Judge struct {
		Address string        `yaml:"address"` // empty: escalations block
		Timeout time.Duration `yaml:"timeout"`
	} `yaml:"judge"`

	State struct {
		Backend       string        `yaml:"backend"` // memory | redis
		RedisURL      string        `yaml:"redis_url"`
		HistorySize   int           `yaml:"history_size"`
		JudgeCacheTTL time.Duration `yaml:"judge_cache_ttl"`
	} `yaml:"state"`

	Audit struct {
		Backend          string   `yaml:"backend"` // none | stdout | kafka
		Brokers          []string `yaml:"brokers"`
		Topic            string   `yaml:"topic"`
		Partitions       int32    `yaml:"partitions"`
		Mode             string   `yaml:"mode"` // async | sync
		IncludeArguments *bool    `yaml:"include_arguments"`
	} `yaml:"audit"`

	// AllowInlineScope lets /v1/check callers send their own scope (the
	// Python SDK does this). Off means only policy-file agents are served.
	AllowInlineScope bool `yaml:"allow_inline_scope"`

	Agents map[string]AgentPolicy          `yaml:"agents"`
	Tools  map[string]rules.RegisteredTool `yaml:"tools"`

	MCP struct {
		Upstreams map[string]string `yaml:"upstreams"`
		// Headers copied from the agent's request to the upstream server.
		ForwardHeaders []string `yaml:"forward_headers"`
	} `yaml:"mcp"`
}

type AgentPolicy struct {
	rules.Scope `yaml:",inline"`
	Upstream    string `yaml:"upstream"`
}

func DefaultConfig() *Config {
	c := &Config{Listen: ":8080"}
	c.Judge.Timeout = 15 * time.Second
	c.State.Backend = "memory"
	c.State.HistorySize = 10
	c.State.JudgeCacheTTL = 10 * time.Minute
	c.Audit.Backend = "none"
	c.Audit.Topic = "agentgate.decisions"
	c.Audit.Partitions = 3
	c.Audit.Mode = "async"
	return c
}

// LoadConfig reads YAML (with ${ENV} expansion) over the defaults, then
// applies AGENTGATE_* environment overrides.
func LoadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(b))), c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	env := func(k string, f func(string)) {
		if v := os.Getenv(k); v != "" {
			f(v)
		}
	}
	env("AGENTGATE_LISTEN", func(v string) { c.Listen = v })
	env("AGENTGATE_JUDGE_ADDRESS", func(v string) { c.Judge.Address = v })
	env("AGENTGATE_REDIS_URL", func(v string) { c.State.Backend, c.State.RedisURL = "redis", v })
	env("AGENTGATE_KAFKA_BROKERS", func(v string) { c.Audit.Backend, c.Audit.Brokers = "kafka", strings.Split(v, ",") })
	env("AGENTGATE_AUDIT_MODE", func(v string) { c.Audit.Mode = v })
	env("AGENTGATE_JUDGE_CACHE_TTL", func(v string) {
		if d, err := time.ParseDuration(v); err == nil {
			c.State.JudgeCacheTTL = d
		}
	})
	env("AGENTGATE_ALLOW_INLINE_SCOPE", func(v string) { c.AllowInlineScope = v == "true" || v == "1" })
	if c.GatewayID == "" {
		c.GatewayID, _ = os.Hostname()
	}
	if c.State.HistorySize <= 0 {
		c.State.HistorySize = 10
	}
	switch c.Audit.Mode {
	case "async", "sync":
	default:
		return nil, fmt.Errorf("audit.mode must be async or sync, got %q", c.Audit.Mode)
	}
	return c, nil
}

func (c *Config) includeArguments() bool {
	return c.Audit.IncludeArguments == nil || *c.Audit.IncludeArguments
}
