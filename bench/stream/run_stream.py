#!/usr/bin/env python3
"""End-to-end streaming test: gateway -> Kafka -> auditor -> PostgreSQL.

Sends N decisions (real dev-set tool calls the rule path decides) round-robin
across both gateway replicas, with faults injected mid-stream:

  * at 1/3: the auditor is killed with SIGKILL and restarted
  * at 2/3: the Kafka broker is restarted

Then it waits for the audit log to catch up and checks:

  * every decision_id the gateways returned is in PostgreSQL (zero loss)
  * no decision_id is stored twice (zero duplicates)
  * the hash chain, signed checkpoints and Kafka cross-check all verify

Usage: python bench/stream/run_stream.py [--decisions 25000] [--concurrency 64]
Requires the compose stack: docker compose up -d --build
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bench.lib import compose, psql, tier1_payloads, verify, wait_ready, write_result  # noqa: E402

GATEWAYS = ["http://localhost:8080", "http://localhost:8081"]


async def fire(n: int, payloads: list[dict], concurrency: int, faults: dict[int, callable]) -> tuple[list[str], int, dict]:
    ids: list[str] = []
    errors = 0
    verdicts: dict[str, int] = {}
    sem = asyncio.Semaphore(concurrency)
    sent = 0
    lock = asyncio.Lock()

    async with httpx.AsyncClient(timeout=30, limits=httpx.Limits(max_connections=concurrency * 2)) as c:
        async def one(i: int) -> None:
            nonlocal errors
            body = dict(payloads[i % len(payloads)], session_id=f"stream-{i % 997}", agent_id="stream")
            async with sem:
                for attempt in range(5):
                    try:
                        r = await c.post(GATEWAYS[i % 2] + "/v1/check", json=body)
                        res = r.json()
                        ids.append(res["decision_id"])
                        verdicts[res["verdict"]] = verdicts.get(res["verdict"], 0) + 1
                        return
                    except (httpx.HTTPError, KeyError, ValueError):
                        await asyncio.sleep(0.5 * (attempt + 1))
                errors += 1

        tasks = []
        for i in range(n):
            if i in faults:
                # fire the fault without stalling the request stream
                threading.Thread(target=faults[i], daemon=True).start()
            tasks.append(asyncio.create_task(one(i)))
            async with lock:
                sent += 1
            if i % 500 == 0:
                await asyncio.sleep(0)  # keep the event loop fair
        await asyncio.gather(*tasks)
    return ids, errors, verdicts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--decisions", type=int, default=25_000)
    ap.add_argument("--concurrency", type=int, default=64)
    ap.add_argument("--no-faults", action="store_true")
    args = ap.parse_args()

    wait_ready(GATEWAYS)
    payloads = tier1_payloads(GATEWAYS[0])
    print(f"payload pool: {len(payloads)} tier-1 tool calls")
    time.sleep(3)
    baseline = int(psql("SELECT count(*) FROM audit_events"))
    started = datetime.now(timezone.utc)

    fault_log: list[dict] = []

    def kill_auditor() -> None:
        t = time.time()
        compose("kill", "-s", "SIGKILL", "auditor")
        compose("up", "-d", "--no-deps", "auditor")
        fault_log.append({"fault": "auditor SIGKILL + restart", "seconds": round(time.time() - t, 1)})

    def restart_kafka() -> None:
        t = time.time()
        compose("restart", "kafka")
        fault_log.append({"fault": "kafka broker restart", "seconds": round(time.time() - t, 1)})

    n = args.decisions
    faults = {} if args.no_faults else {n // 3: kill_auditor, 2 * n // 3: restart_kafka}
    t0 = time.time()
    ids, errors, verdicts = asyncio.run(fire(n, payloads, args.concurrency, faults))
    send_s = time.time() - t0
    print(f"sent {len(ids)} decisions in {send_s:.1f}s ({errors} client errors); faults: {fault_log}")

    # Wait for the auditor to drain Kafka into PostgreSQL.
    deadline = time.time() + 300
    stored = 0
    while time.time() < deadline:
        stored = int(psql("SELECT count(*) FROM audit_events")) - baseline
        if stored >= len(ids):
            break
        time.sleep(2)
    drain_s = time.time() - t0 - send_s
    print(f"audit rows for this run: {stored} (waited {drain_s:.1f}s after sending)")

    # Set comparison on decision IDs.
    since = started.isoformat()
    rows = psql(f"SELECT event_id FROM audit_events WHERE ingested_at >= '{since}'").split()
    stored_ids = set(rows)
    sent_ids = set(ids)
    missing = sent_ids - stored_ids
    dup_count = int(psql("SELECT count(*) - count(DISTINCT event_id) FROM audit_events"))
    print(f"missing: {len(missing)}  duplicates: {dup_count}")

    report = verify()
    print(f"verifier: ok={report['ok']} rows={report['rows_verified']} "
          f"kafka-matched={report.get('rows_cross_checked_with_kafka')} checkpoints={report['checkpoints_verified']}")

    result = {
        "date": started.isoformat(timespec="seconds"),
        "decisions_sent": len(ids), "client_errors": errors, "verdicts": verdicts,
        "gateways": GATEWAYS, "faults_injected": fault_log,
        "send_seconds": round(send_s, 1), "send_rate_per_s": round(len(ids) / send_s, 1),
        "rows_stored_for_run": stored, "missing": len(missing), "duplicates_in_table": dup_count,
        "missing_sample": sorted(missing)[:10],
        "verifier": {k: report[k] for k in ("ok", "chains", "rows_verified", "rows_cross_checked_with_kafka",
                                           "checkpoints_verified", "checkpoints_signed", "problems")},
        "zero_loss": len(missing) == 0 and errors == 0, "zero_duplicates": dup_count == 0,
    }
    path = write_result("stream", f"stream_{len(ids)}.json", result)
    print(f"wrote {path.relative_to(Path.cwd()) if path.is_relative_to(Path.cwd()) else path}")
    if not (result["zero_loss"] and result["zero_duplicates"] and report["ok"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
