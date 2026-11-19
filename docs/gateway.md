# Running the gateway

```bash
git clone https://github.com/arhaamatiq/agentgate && cd agentgate
export OPENAI_API_KEY=sk-...        # optional: without it, ambiguous calls are blocked
docker compose up -d --build
```

This starts two gateway replicas (`:8080`, `:8081`), the LLM judge, Redis,
Kafka, PostgreSQL, the audit writer, and a demo MCP server reachable only
through the gateway. Policy lives in [`deploy/policy.yaml`](../deploy/policy.yaml)
(see [policies.md](policies.md)). Kubernetes manifests are in
[`deploy/k8s`](../deploy/k8s) (`kubectl apply -k deploy/k8s/overlays/dev`).

## Deciding calls

```bash
curl -s localhost:8080/v1/check -d '{"agent_id":"reporting-agent","tool_name":"execute_sql",
  "arguments":{"query":"DROP TABLE sales"}}'
# {"verdict":"block","tier":1,"policy":"scope_operation","reasoning":"Operation 'destructive' not in allowed operations: ['read']", ...}
```

Or speak MCP: point any MCP client at `http://localhost:8080/mcp/reporting-agent`.
A blocked call comes back to the model as a tool error that says why, so the
model can correct course instead of retrying blindly.

The Python library can use the gateway as its engine (install from source until
the next PyPI release): `agentgate.protect_all(gateway_url="http://agentgate:8080")`.

## Local MCP servers

Install the binary and wrap any stdio MCP server; the gateway runs as a filter
in front of it:

```bash
go install github.com/arhaamatiq/agentgate/gateway/cmd/agentgate-gateway@latest
```

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

## Fail-closed behavior

| If this fails... | ...the call is |
|---|---|
| Judge down, slow (deadline), or its model errors | blocked (`judge_unavailable` / `tier2_error`) |
| A rule panics, or arguments can't be analyzed | blocked (`rule_engine_error`) |
| Redis unreachable (trajectory or rate-limit state) | blocked (`state_unavailable`) |
| Audit pipeline can't take the record | blocked (`audit_unavailable`) |
| Agent has no policy | blocked (`unknown_agent`) |
| The gateway itself | unreachable tools: MCP servers are routable only through it (NetworkPolicy); the Python SDK blocks on any non-`allow` answer |

## Verifying the audit log

Recomputes every hash, checks the signed checkpoints, and matches every row to
its Kafka source:

```bash
docker compose run --rm --entrypoint agentgate-auditor auditor verify \
  --dsn postgres://agentgate_reader:reader-dev-only@postgres:5432/agentgate \
  --brokers kafka:9092 --public-key GbWTR3bGXr1hHEc6wZ6c8UrdM7ZCevxcppq4fctVbEc= --kafka-crosscheck
```
