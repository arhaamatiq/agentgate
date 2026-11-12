"""Shared helpers for the benchmark scripts (they drive the docker compose stack)."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results"
PUBLIC_KEY = "GbWTR3bGXr1hHEc6wZ6c8UrdM7ZCevxcppq4fctVbEc="  # pairs with the DEV key in docker-compose.yml
READER_DSN = "postgres://agentgate_reader:reader-dev-only@postgres:5432/agentgate?sslmode=disable"
ADMIN = ["psql", "-U", "agentgate_admin", "-d", "agentgate", "-v", "ON_ERROR_STOP=1", "-tA"]


def compose(*args: str, check: bool = True, capture: bool = True, env: dict | None = None) -> str:
    import os
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run(["docker", "compose", *args], cwd=ROOT, text=True, env=e,
                       stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)} failed:\n{p.stdout}")
    return p.stdout or ""


def psql(sql: str, db: str = "agentgate", check: bool = True) -> str:
    cmd = ["exec", "-T", "postgres", "psql", "-U", "agentgate_admin", "-d", db, "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql]
    return compose(*cmd, check=check).strip()


def verify(dsn: str = READER_DSN, crosscheck: bool = True) -> dict[str, Any]:
    args = ["run", "--rm", "--no-deps", "--entrypoint", "/usr/local/bin/agentgate-auditor", "auditor", "verify",
            "--dsn", dsn, "--brokers", "kafka:9092", "--public-key", PUBLIC_KEY, "--json"]
    if crosscheck:
        args.append("--kafka-crosscheck")
    out = compose(*args, check=False)
    start = out.find("{")
    if start < 0:
        raise RuntimeError(f"verifier produced no report:\n{out}")
    return json.loads(out[start:out.rfind("}") + 1])


def wait_ready(urls: list[str], timeout: float = 120) -> None:
    deadline = time.time() + timeout
    for u in urls:
        while True:
            try:
                if httpx.get(u + "/readyz", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.time() > deadline:
                raise RuntimeError(f"{u} not ready after {timeout}s")
            time.sleep(1)


def tier1_payloads(gateway: str, dataset: Path | None = None) -> list[dict]:
    """Real dev-set tool calls the rule path decides on its own (no LLM cost)."""
    dataset = dataset or ROOT / "bench" / "data" / "dev_set.jsonl"
    out = []
    with httpx.Client(timeout=30) as c:
        for line in dataset.read_text().splitlines():
            case = json.loads(line)
            scope = dict(case["scope"], task=case["task"])
            for st in case["steps"]:
                body = {"agent_id": "probe", "session_id": "probe", "task": case["task"], "scope": scope,
                        "tool_name": st["tool_name"], "arguments": st["arguments"]}
                if c.post(gateway + "/v1/check", json=body).json().get("tier") == 1:
                    out.append(body)
    return out


def write_result(subdir: str, name: str, data: dict) -> Path:
    d = RESULTS / subdir
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(json.dumps(data, indent=2) + "\n")
    return p
