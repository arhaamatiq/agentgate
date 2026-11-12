# AgentGate

### A fail-closed firewall for what AI agents *do*

> Guardrails check what an agent **says**. AgentGate checks every tool call an
> agent **makes**, before it runs: SQL, files, HTTP, shell, email, MCP tools.

![AgentGate Demo](docs/demo.png)

[![PyPI](https://img.shields.io/pypi/v/agentgate-py?color=red&label=agentgate-py)](https://pypi.org/project/agentgate-py/)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](https://pypi.org/project/agentgate-py/)
[![Go](https://img.shields.io/badge/go-1.26+-00ADD8)](gateway/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An agent told to "generate the Q4 report" that reads a poisoned document can
call `execute_sql("DELETE FROM users")` while its chat output says "processing
your request". AgentGate sits on the execution path, so the call is decided
before the tool runs, and a blocked call never reaches the database.

You declare what an agent is **allowed** to do; anything else is blocked or, if
genuinely ambiguous, judged by a separate LLM. Every failure mode blocks.

```yaml
agents:
  reporting-agent:
    task: Produce the weekly sales report from the analytics database.
    allowed_operations: [read]
    allowed_resources: [sales, orders, products, /reports]
```

An operation is a class the engine infers (`read`, `write`, `send`, `export`,
`deploy`, `config`, `execute`, `destructive`, `http`), a tool's own verb, or the
tool's full name. `[delete]` permits `delete_file` but never `write_file` or a
SQL `DROP`; `[restart_service]` permits that tool; `destructive` always has to
be declared. A file tool is a `read` only if its name says so (`read_file`,
`list_directory`, `search_files`); `edit_file` or `move_file` is a `write`, and
`send_file` a `send`. A call that only reads, such as a GET to a URL listed in
`allowed_resources` or a bare `df -h`, passes a `read` scope.

An absolute path in `allowed_resources` covers that path and what is under it,
never its parent or a sibling: `/srv/finance/reports` does not allow `/srv`.
A URL covers itself and what is under its path, never another host:
`https://api.example.com` does not allow `https://api.example.com.evil.net`.
A path inside an allowed resource such as `/var/log/app/` still gets checked
for credential files, traversal and encoding tricks; only location guesses
(system directories, `*.conf`, `backups/`) defer to the grant, and those calls
go to the LLM judge instead of being blocked outright.

---

## Two ways to run it

| | **Python library** | **Gateway** |
|---|---|---|
| What | In-process interceptors for OpenAI, LangChain and plain functions | Go MCP gateway + Python LLM judge + audit pipeline |
| Install | `pip install agentgate-py` | `docker compose up -d` or `kubectl apply -k deploy/k8s/overlays/dev` |
| Best for | One Python agent, zero infrastructure | Many agents, any language, MCP clients (desktop apps, IDEs, ...), central policy and audit |
| Decisions | Same rules, same judge prompt | Same rules (verified against the Python engine), judge over gRPC |
| Audit | Optional Supabase logging | Kafka → hash-chained, append-only Postgres log with a verifier |

The Python library can also use the gateway as its engine:
`agentgate.protect_all(gateway_url="http://agentgate:8080")`.

---

## Quick start: Python library

```bash
pip install agentgate-py
```

```python
import agentgate

agentgate.protect_all()          # patches the OpenAI SDK and LangChain if installed

with agentgate.scope(
    task="Generate Q4 sales report",
    allowed_operations=["read"],
    allowed_resources=["sales", "reports"],
):
    run_agent()                  # out-of-scope tool calls raise FirewallBlockedError
```

Or guard functions directly:

```python
@agentgate.guard
def execute_sql(query: str) -> str: ...
```

Ambiguous calls go to the LLM judge (`OPENAI_API_KEY`, or any OpenAI-compatible
endpoint via `AGENTGATE_JUDGE_BASE_URL`). Without a judge, they are blocked.

Try it without any key: `python examples/demo_agent/run_demo.py`.

## Quick start: gateway

```bash
git clone https://github.com/arhaamatiq/agentgate && cd agentgate
export OPENAI_API_KEY=sk-...        # optional: without it, ambiguous calls are blocked
docker compose up -d --build
```

This starts two gateway replicas (`:8080`, `:8081`), the LLM judge, Redis,
Kafka, PostgreSQL, the audit writer, and a demo MCP server reachable only
through the gateway. Policy lives in [`deploy/policy.yaml`](deploy/policy.yaml).

```bash
# Decide one call
curl -s localhost:8080/v1/check -d '{"agent_id":"reporting-agent","tool_name":"execute_sql",
  "arguments":{"query":"DROP TABLE sales"}}'
# {"verdict":"block","tier":1,"policy":"scope_operation","reasoning":"Operation 'destructive' not in allowed operations: ['read']", ...}

# Or speak MCP: point any MCP client at http://localhost:8080/mcp/reporting-agent
```

**Local MCP servers (desktop and IDE MCP clients).** Install the binary
(`go install github.com/arhaamatiq/agentgate/gateway/cmd/agentgate-gateway@latest`)
and wrap any stdio MCP server; the gateway runs as a filter in front of it:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentgate-gateway",
      "args": ["stdio", "--config", "policy.yaml", "--agent", "devops-agent", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/var/app"]
    }
  }
}
```

A blocked call comes back to the model as a tool error that says why, so the
model can correct course instead of retrying blindly.

**Verify the audit log** (recomputes every hash, checks signed checkpoints, and
matches every row to its Kafka source):

```bash
docker compose run --rm --entrypoint agentgate-auditor auditor verify \
  --dsn postgres://agentgate_reader:reader-dev-only@postgres:5432/agentgate \
  --brokers kafka:9092 --public-key GbWTR3bGXr1hHEc6wZ6c8UrdM7ZCevxcppq4fctVbEc= --kafka-crosscheck
```

---

## How it works

```mermaid
flowchart LR
    A[Agent / MCP client] -->|tools/call or /v1/check| G[Go gateway<br/>rule path]
    G -->|ambiguous only, gRPC| J[Python LLM judge]
    G <-->|trajectory, verdict cache,<br/>rate limits| R[(Redis)]
    G -->|allowed calls only| T[MCP tool servers]
    G -->|every decision| K[[Kafka]]
    K --> W[Auditor] -->|hash-chained, append-only| P[(PostgreSQL)]
    W -->|signed checkpoints| K
```

1. **Rule path (Tier 1, in-process).** Scope check (operation and resource),
   then a domain analyzer: SQL (lexer, statement classification, injection
   indicators), filesystem (multi-layer decoding: double URL encoding, overlong
   UTF-8, NFKC; traversal, system paths, secrets), HTTP (SSRF: private ranges,
   cloud metadata, obfuscated IPs, DNS rebinding), shell. Most calls end here
   in well under a millisecond.
2. **LLM judge (Tier 2, gRPC).** Only calls the rules can't settle. A separate
   model (never the agent's own) scores scope, blast radius, reversibility,
   trajectory and red flags, using the session's last 10 calls to catch
   read-then-exfiltrate chains. Redis shares that trajectory across replicas.
3. **Audit.** Every decision goes to Kafka, then to PostgreSQL as a SHA-256
   hash chain per partition, with the Kafka offset stored in the same
   transaction (no loss, no duplicates on crash). Ed25519-signed chain-head
   checkpoints go to a separate topic, so even a database superuser who
   rewrites the chain is caught.

### Fail-closed, by construction

| If this fails... | ...the call is |
|---|---|
| Judge down, slow (deadline), or its model errors | blocked (`judge_unavailable` / `tier2_error`) |
| A rule panics, or arguments can't be analyzed | blocked (`rule_engine_error`) |
| Redis unreachable (trajectory or rate-limit state) | blocked (`state_unavailable`) |
| Audit pipeline can't take the record | blocked (`audit_unavailable`) |
| Agent has no policy | blocked (`unknown_agent`) |
| The gateway itself | unreachable tools: MCP servers are routable only through it (NetworkPolicy); the Python SDK blocks on any non-`allow` answer |

---

## Results

<!-- results:start -->
| | Result |
|---|---|
| Adversarial dev benchmark, 466 decisions (development set) | recall 99.7%, precision 97.2% via the gateway; 99.6% / 98.1% in run 007, up from 67.3% recall in run 001 |
| Go rule engine vs Python reference | 48,550 of 48,716 fuzzed and benchmark inputs identical, 0 more permissive |
| Calls settled by rules alone (no LLM) | 280 of 466 (60%) on the dev set |
<!-- results:end -->

Full methodology, every run, and caveats: **[RESULTS.md](RESULTS.md)** and
**[bench/results/HISTORY.md](bench/results/HISTORY.md)**. Reproduce with
`make bench` (no API key needed: the judge replays recorded responses).

---

## Repository layout

```
agentgate/            Python library (pip install agentgate-py) and the gRPC judge service
gateway/              Go: gateway, auditor, load generator, demo MCP server
  internal/rules/       rule engine (parity-tested against the Python engine)
  internal/audit/       Kafka producer, hash-chain writer, verifier
proto/                gRPC contract between gateway and judge
deploy/               policy.yaml, Kubernetes (kustomize base + dev overlay)
bench/                frozen datasets and every benchmark script
agenttest/            original adversarial suite and run reports 001-007
```

## Development

```bash
make dev        # Python deps
make test       # pytest + go test (includes the 50k-case parity test)
make up         # compose stack
make bench      # all benchmarks, then regenerate RESULTS.md
```

## License

MIT, see [LICENSE](LICENSE). Built by [Arhaam Atiq](https://github.com/arhaamatiq).
