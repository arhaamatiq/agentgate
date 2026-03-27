# AgentGate

**Guardrails AI protects what LLMs *say*. AgentGate protects what agents *do*.**

AgentGate is an action-level firewall for AI agents. It intercepts every tool call at the Python execution layer — before any side effect occurs. When an agent calls `execute_sql("DROP TABLE users")`, text-level guardrails don't catch it. AgentGate does.

## How It Compares

| Feature | Guardrails AI | NeMo Guardrails | **AgentGate** |
|---|---|---|---|
| Protects | LLM outputs (text) | Conversational flow | **Tool calls (actions)** |
| Intercepts at | Text generation | Dialog management | **Execution layer** |
| SQL injection detection | No | No | **Yes — AST analysis** |
| SSRF prevention | No | No | **Yes — IP/metadata checks** |
| Path traversal detection | No | No | **Yes — multi-pattern** |
| Scope-based policies | No | Partial | **Yes — allow-first model** |
| Two-tier evaluation | No | No | **Static + LLM-as-judge** |
| Audit trail | No | Logs | **Full Supabase audit log** |
| Setup complexity | Moderate | High | **One line** |

## Quick Start (< 5 minutes)

### 1. Install

```bash
uv add agentgate
# or
pip install agentgate
```

### 2. One-Line Protection

```python
import agentgate

agentgate.protect_all()  # auto-patches LangChain, OpenAI SDK

# Your existing agent code — zero modifications needed
agent.run("Generate the monthly sales report")
```

That's it. Every tool call your agent makes is now intercepted, evaluated, and logged.

### 3. Optional: Scope Declaration

For stronger guarantees, declare what the agent is allowed to do:

```python
with agentgate.scope(
    task="Generate the monthly sales report",
    allowed_resources=["sales_data", "reports"],
    allowed_operations=["read", "aggregate", "write"],
):
    agent.run(task)
```

### 4. Optional: Config File

Define scopes once in `agentgate.yaml`:

```yaml
agents:
  reporting_agent:
    allowed_operations: [read, aggregate, write_report]
    allowed_resources: [sales_data, reports_output]
```

```python
agentgate.protect_all(config="agentgate.yaml")
```

### 5. Guard Raw Functions

For functions outside a framework:

```python
@agentgate.guard
def execute_sql(query: str) -> str:
    return db.execute(query)

execute_sql("SELECT * FROM users")      # ✅ Allowed
execute_sql("DROP TABLE users")          # 🛑 FirewallBlockedError
```

## Architecture

```
Agent Tool Call
       │
       ▼
┌──────────────────────────────────────────────┐
│              AgentGate Firewall               │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │           TIER 1 — Fast Path            │  │
│  │         (sync, < 2ms, no API)           │  │
│  │                                         │  │
│  │  1. Scope check (allowed ops/resources) │  │
│  │  2. Static analysis:                    │  │
│  │     • SQL:  sqlparse AST → destructive? │  │
│  │     • FS:   path traversal patterns     │  │
│  │     • HTTP: SSRF / metadata endpoints   │  │
│  │     • Rate: sliding window per agent    │  │
│  │                                         │  │
│  │  Clear verdict? ──────► ALLOW or BLOCK  │  │
│  │  Ambiguous? ──────────► escalate ↓      │  │
│  └─────────────────────────┬───────────────┘  │
│                            │                  │
│  ┌─────────────────────────▼───────────────┐  │
│  │        TIER 2 — Semantic Judge          │  │
│  │     (async, 100-400ms, gpt-4o-mini)     │  │
│  │                                         │  │
│  │  Separate LLM client (reviewer, not     │  │
│  │  participant). Evaluates:               │  │
│  │  • Task consistency                     │  │
│  │  • Blast radius proportionality         │  │
│  │  • Action reversibility                 │  │
│  │                                         │  │
│  │  → { consistent, confidence, reasoning} │  │
│  └─────────────────────────────────────────┘  │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │         Audit Logger (async)            │  │
│  │   Fire-and-forget → Supabase            │  │
│  │   actions + violations tables           │  │
│  └─────────────────────────────────────────┘  │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │       Context Propagation               │  │
│  │   agent_id, task_id, user_id,           │  │
│  │   action_history (contextvars)          │  │
│  └─────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
       │
       ▼
  ALLOW → execute tool    BLOCK → FirewallBlockedError
```

## Context Propagation

AgentGate uses Python `contextvars` for thread-safe, async-safe identity tracking:

```python
from agentgate import agent_context

with agent_context(agent_id="report-bot", task_id="run-42", user_id="alice"):
    agent.run(task)  # all tool calls automatically carry this context
```

## Audit Logging

Every intercepted action is logged to Supabase (when configured):

```bash
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-service-role-key"
```

**Schema:**

- `actions` — every tool call: id, agent_id, task_id, tool_name, payload, verdict, tier_used, reasoning
- `violations` — blocked calls: id, action_id (FK), severity, details

Logging is async and fire-and-forget — verified to add < 5ms overhead.

## Supabase Schema

```sql
CREATE TABLE actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT now(),
    agent_id TEXT,
    task_id TEXT,
    user_id TEXT,
    tool_name TEXT NOT NULL,
    payload JSONB DEFAULT '{}',
    verdict TEXT NOT NULL,
    policy_name TEXT,
    severity TEXT DEFAULT 'low',
    tier_used INTEGER DEFAULT 1,
    reasoning TEXT
);

CREATE TABLE violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID REFERENCES actions(id),
    created_at TIMESTAMPTZ DEFAULT now(),
    severity TEXT DEFAULT 'low',
    details JSONB DEFAULT '{}'
);

CREATE INDEX idx_actions_agent ON actions(agent_id);
CREATE INDEX idx_actions_task ON actions(task_id);
CREATE INDEX idx_actions_created ON actions(created_at DESC);
CREATE INDEX idx_violations_action ON violations(action_id);
CREATE INDEX idx_violations_severity ON violations(severity);
```

## Known Limitations

1. **Framework coverage** — Currently patches LangChain (`BaseTool._run`/`_arun`) and OpenAI SDK (`chat.completions.create`). CrewAI, AutoGen, and other frameworks are not yet supported.
2. **Streaming responses** — The OpenAI interceptor does not yet handle streaming tool calls (`stream=True`).
3. **DNS rebinding** — The HTTP analyzer checks IPs at analysis time. DNS rebinding attacks that resolve differently at execution time are not caught.
4. **Multi-agent coordination** — Scope policies are per-agent. Cross-agent policy orchestration is not yet supported.
5. **Tier 2 latency** — When Tier 2 is triggered, expect 100-400ms added latency for the LLM evaluation.
6. **No persistent policy store** — Policies are in-memory or YAML. A policy management API is planned.

## Roadmap (v2)

- **Real-time Dashboard** — Next.js dashboard connected to Supabase Realtime (`postgres_changes`). The schema is already designed for this — no migration needed.
- **Demo Agent** — A complete demo agent (direct OpenAI SDK) showing AgentGate in action.
- **Adversarial Eval Suite** — 50+ test cases measuring precision, recall, and F1 for the evaluation engine.
- **Additional Interceptors** — CrewAI, AutoGen, Anthropic SDK.
- **Policy Management API** — CRUD endpoints for runtime policy updates.

## Development

```bash
# Install with dev dependencies
make dev

# Run tests
make test

# Run timing tests specifically
make test-timing

# Lint
make lint

# Format
make format
```

## License

MIT
