#!/usr/bin/env python3
"""Fail-closed integration test against the running compose stack.

Each scenario breaks one component, sends tool calls through the MCP path
(agent -> gateway /mcp/<agent> -> demo MCP server), and checks:

  * the gateway answered BLOCK, and
  * the call never reached the tool server (its execution log is unchanged).

Scenarios:
  judge_down        judge container stopped
  judge_hung        judge container paused (gRPC deadline expires)
  judge_llm_error   judge restarted with an invalid model API key
  redis_down        shared state unavailable
  audit_down_sync   Kafka stopped while the gateway runs in sync audit mode
  gateway_down      the Python SDK (remote mode) cannot reach the gateway;
                    and an agent on the agents network cannot reach the tool
                    server directly
  rule_fault        argument shapes the rule engine cannot analyze, plus the
                    Go unit test that injects a panic into rule evaluation

Usage: python bench/failclosed/run_failclosed.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from bench.lib import compose, wait_ready, write_result  # noqa: E402

GW = "http://localhost:8080"
AGENT = "reporting-agent"
SAFE = {"name": "execute_sql", "arguments": {"query": "SELECT region, SUM(total) FROM sales GROUP BY region"}}
ESCALATING = {"name": "execute_sql", "arguments": {"query": "SELECT * FROM customer_payment_methods"}}
PROBE_IMAGE = "python:3.12-slim"


def mcp_call(tool: dict, timeout: float = 30) -> dict:
    body = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": "tools/call", "params": tool}
    t0 = time.time()
    try:
        r = httpx.post(f"{GW}/mcp/{AGENT}", json=body, timeout=timeout)
        res = r.json()
    except Exception as e:
        return {"transport_error": f"{type(e).__name__}", "seconds": round(time.time() - t0, 2)}
    blocked = bool(res.get("result", {}).get("isError"))
    info = res.get("result", {}).get("structuredContent", {}).get("agentgate", {})
    return {"blocked": blocked, "policy": info.get("policy"), "fail_closed": info.get("fail_closed"),
            "seconds": round(time.time() - t0, 2)}


def executed_count() -> int:
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", "agent-gate_backend", PROBE_IMAGE, "python", "-c",
         "import urllib.request,json;print(json.load(urllib.request.urlopen('http://mcp-server:9000/executed'))['count'])"],
        capture_output=True, text=True)
    return int(out.stdout.strip())


def scenario(name: str, breaker, restorer, calls: list[dict], expect_policy: set[str], timeout: float = 30) -> dict:
    before = executed_count()
    t0 = time.time()
    breaker()
    results = [mcp_call(c, timeout) for c in calls]
    restorer()
    after = executed_count()
    passed = all(r.get("blocked") or "transport_error" in r for r in results) and after == before
    policies_ok = all(r.get("policy") in expect_policy for r in results if r.get("blocked"))
    out = {"scenario": name, "calls": results, "tool_server_executions_during": after - before,
           "pass": passed and policies_ok, "seconds": round(time.time() - t0, 1)}
    print(f"{name:16} pass={out['pass']}  {[(r.get('policy'), r.get('seconds')) for r in results]}  "
          f"executions={after - before}")
    return out


def main() -> None:
    wait_ready([GW, "http://localhost:8081"])
    env_base = {"AGENTGATE_JUDGE_CACHE_TTL": "0"}
    out = []

    # Sanity: with everything up, a safe call reaches the tool server.
    before = executed_count()
    ok = mcp_call(SAFE)
    healthy = {"scenario": "control_all_up", "calls": [ok], "tool_server_executions_during": executed_count() - before}
    healthy["pass"] = not ok.get("blocked") and healthy["tool_server_executions_during"] == 1
    print(f"control          pass={healthy['pass']} (safe call executed)")
    out.append(healthy)

    out.append(scenario("judge_down", lambda: compose("stop", "judge"), lambda: compose("start", "judge"),
                        [ESCALATING], {"judge_unavailable"}))
    out.append(scenario("judge_hung", lambda: compose("pause", "judge"), lambda: compose("unpause", "judge"),
                        [ESCALATING], {"judge_unavailable"}, timeout=60))

    def bad_key():
        compose("up", "-d", "--no-deps", "judge", env={"OPENAI_API_KEY": "sk-invalid", "AGENTGATE_JUDGE_CASSETTE": "",
                                                       **env_base})
        time.sleep(6)

    def restore_judge():
        compose("up", "-d", "--no-deps", "judge", env=env_base)
        time.sleep(6)
    out.append(scenario("judge_llm_error", bad_key, restore_judge, [ESCALATING], {"tier2_error"}))

    out.append(scenario("redis_down", lambda: compose("stop", "redis"),
                        lambda: (compose("start", "redis"), time.sleep(3)), [SAFE, ESCALATING], {"state_unavailable"}))

    def kafka_down_sync():
        compose("up", "-d", "--no-deps", "gateway", env={"AGENTGATE_AUDIT_MODE": "sync", **env_base})
        wait_ready([GW])
        compose("stop", "kafka")

    def restore_kafka():
        compose("start", "kafka")
        time.sleep(10)
        compose("up", "-d", "--no-deps", "gateway", env=env_base)
        wait_ready([GW])
    out.append(scenario("audit_down_sync", kafka_down_sync, restore_kafka, [SAFE], {"audit_unavailable"}, timeout=60))

    # Gateway down: SDK blocks; agents have no direct route to tools.
    compose("stop", "gateway", "gateway-2")
    sdk = subprocess.run([sys.executable, "-c", (
        "import agentgate\n"
        "from agentgate.firewall import FirewallBlockedError\n"
        "agentgate.protect_all(gateway_url='http://localhost:8080')\n"
        "@agentgate.guard\n"
        "def execute_sql(query): return 'ran'\n"
        "with agentgate.scope(task='report', allowed_operations=['read'], allowed_resources=['sales']):\n"
        "    try:\n"
        "        execute_sql('SELECT 1 FROM sales'); print('ALLOWED')\n"
        "    except FirewallBlockedError as e: print('BLOCKED', e.verdict.policy_name)\n")],
        capture_output=True, text=True, cwd=ROOT, env={**os.environ, "OPENAI_API_KEY": ""})
    direct = subprocess.run(
        ["docker", "run", "--rm", "--network", "agent-gate_agents", PROBE_IMAGE, "python", "-c",
         "import urllib.request\n"
         "try:\n urllib.request.urlopen('http://mcp-server:9000/mcp', timeout=5); print('REACHABLE')\n"
         "except Exception as e: print('UNREACHABLE', type(e).__name__)\n"],
        capture_output=True, text=True)
    compose("start", "gateway", "gateway-2")
    wait_ready([GW, "http://localhost:8081"])
    gd = {"scenario": "gateway_down", "python_sdk": sdk.stdout.strip(), "agent_direct_to_tool_server": direct.stdout.strip()}
    gd["pass"] = sdk.stdout.startswith("BLOCKED gateway_unavailable") and direct.stdout.startswith("UNREACHABLE")
    print(f"gateway_down     pass={gd['pass']}  sdk={gd['python_sdk']!r} direct={gd['agent_direct_to_tool_server']!r}")
    out.append(gd)

    weird = [{"name": "execute_sql", "arguments": {"query": ["DROP TABLE sales"]}},
             {"name": "read_file", "arguments": {"path": {"nested": "/etc/passwd"}}}]
    out.append(scenario("rule_fault", lambda: None, lambda: None, weird, {"rule_engine_error"}))
    unit = subprocess.run(["go", "test", "./internal/rules/", "-run", "FailClosed", "-count=1", "-v"],
                          cwd=ROOT / "gateway", capture_output=True, text=True)
    out[-1]["go_unit_test_panic_injection"] = "PASS" if unit.returncode == 0 else unit.stdout[-500:]
    out[-1]["pass"] = out[-1]["pass"] and unit.returncode == 0

    summary = {"scenarios": out, "all_pass": all(s["pass"] for s in out)}
    write_result("failclosed", "failclosed.json", summary)
    print("ALL PASS" if summary["all_pass"] else "FAILURES — see bench/results/failclosed/failclosed.json")
    if not summary["all_pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
