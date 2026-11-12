#!/usr/bin/env python3
"""Tamper-evidence test for the audit log.

1. Shows the table is append-only: the writer role cannot UPDATE, and even
   the table owner's UPDATE/DELETE/TRUNCATE are rejected by triggers.
2. Simulates an attacker with full database superuser access (triggers
   disabled) in a scratch copy of the log, one attack at a time, and runs
   the verifier after each:

     edit_event        change a BLOCK event to ALLOW (event text and column)
     edit_column       change only the verdict column
     delete_middle     delete one row in the middle of a chain
     truncate_tail     delete the newest 100 rows of a chain
     rewrite_chain     edit a row, then recompute every later hash so the
                       chain is internally consistent again
     forge_append      append a fabricated ALLOW event with a valid hash

   The attacks run against a copy (database tamper_lab) so the real log
   stays intact. Signed checkpoints and the Kafka cross-check are read from
   the live Kafka topics, exactly as an auditor would.

Usage: python bench/stream/tamper.py      (stack up, with rows in the log)
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bench.lib import compose, psql, verify, write_result  # noqa: E402

ADMIN_HOST = "postgresql://agentgate_admin:admin-dev-only@127.0.0.1:55432/"
LAB_DSN_IN_NETWORK = "postgres://agentgate_admin:admin-dev-only@postgres:5432/tamper_lab?sslmode=disable"


def link_hash(prev: bytes, chain: int, seq: int, event: str) -> bytes:
    # Independent re-implementation of audit.LinkHash.
    return hashlib.sha256(prev + chain.to_bytes(4, "big") + seq.to_bytes(8, "big") + event.encode()).digest()


def append_only_checks() -> dict:
    out = {}
    w = compose("exec", "-T", "postgres", "psql",
                "postgres://agentgate_writer:writer-dev-only@localhost:5432/agentgate", "-c",
                "UPDATE audit_events SET verdict = 'allow' WHERE seq = 1", check=False)
    out["writer_update"] = "rejected" if "permission denied" in w else f"NOT REJECTED: {w.strip()}"
    for stmt in ("UPDATE audit_events SET verdict = 'allow' WHERE seq = 1",
                 "DELETE FROM audit_events WHERE seq = 1", "TRUNCATE audit_events"):
        r = compose("exec", "-T", "postgres", "psql", "-U", "agentgate_admin", "-d", "agentgate", "-c", stmt, check=False)
        out[f"owner_{stmt.split()[0].lower()}"] = "rejected" if "append-only" in r else f"NOT REJECTED: {r.strip()}"
    return out


def fresh_lab() -> None:
    psql("DROP DATABASE IF EXISTS tamper_lab")
    psql("CREATE DATABASE tamper_lab")
    compose("exec", "-T", "postgres", "sh", "-c",
            "pg_dump -U agentgate_admin -d agentgate -t audit_events | psql -q -U agentgate_admin -d tamper_lab")
    psql("ALTER TABLE audit_events DISABLE TRIGGER USER", db="tamper_lab")


def lab() -> psycopg.Connection:
    return psycopg.connect(ADMIN_HOST + "tamper_lab", autocommit=True)


def biggest_chain(c: psycopg.Connection) -> tuple[int, int]:
    return c.execute("SELECT chain_id, max(seq) FROM audit_events GROUP BY chain_id ORDER BY 2 DESC LIMIT 1").fetchone()


def a_block_row(c, chain, below):
    return c.execute("SELECT seq FROM audit_events WHERE chain_id=%s AND verdict='block' AND seq < %s "
                     "ORDER BY seq DESC LIMIT 1", (chain, below)).fetchone()[0]


def attack(name: str) -> dict:
    fresh_lab()
    with lab() as c:
        chain, head = biggest_chain(c)
        mid = head // 2
        if name == "edit_event":
            seq = a_block_row(c, chain, mid)
            c.execute("UPDATE audit_events SET event = replace(event, '\"verdict\":\"block\"', '\"verdict\":\"allow\"'), "
                      "verdict='allow' WHERE chain_id=%s AND seq=%s", (chain, seq))
        elif name == "edit_column":
            seq = a_block_row(c, chain, mid)
            c.execute("UPDATE audit_events SET verdict='allow' WHERE chain_id=%s AND seq=%s", (chain, seq))
        elif name == "delete_middle":
            seq = mid
            c.execute("DELETE FROM audit_events WHERE chain_id=%s AND seq=%s", (chain, seq))
        elif name == "truncate_tail":
            seq = head - 99
            c.execute("DELETE FROM audit_events WHERE chain_id=%s AND seq>=%s", (chain, seq))
        elif name == "rewrite_chain":
            seq = a_block_row(c, chain, mid)
            rows = c.execute("SELECT seq, event, prev_hash FROM audit_events WHERE chain_id=%s AND seq>=%s ORDER BY seq",
                             (chain, seq)).fetchall()
            prev = bytes(rows[0][2])
            for s, ev, _ in rows:
                if s == seq:
                    ev = ev.replace('"verdict":"block"', '"verdict":"allow"')
                h = link_hash(prev, chain, s, ev)
                c.execute("UPDATE audit_events SET event=%s, verdict=%s, prev_hash=%s, hash=%s WHERE chain_id=%s AND seq=%s",
                          (ev, json.loads(ev).get("verdict", "allow"), prev, h, chain, s))
                prev = h
        elif name == "forge_append":
            seq = head + 1
            prev_hash, offset = c.execute("SELECT hash, kafka_offset FROM audit_events WHERE chain_id=%s AND seq=%s",
                                          (chain, head)).fetchone()
            eid = str(uuid.uuid4())
            ev = json.dumps({"v": 1, "event_id": eid, "ts": "2026-11-04T00:00:00Z", "gateway": "forged",
                             "source": "api", "agent_id": "attacker", "session_id": "x", "tool_name": "execute_sql",
                             "args_sha256": "0" * 64, "verdict": "allow", "tier": 1, "policy": "sql_analysis",
                             "severity": "low", "reasoning": "looks fine", "fail_closed": False, "cached": False,
                             "latency_us": 10}, separators=(",", ":"))
            c.execute("INSERT INTO audit_events (chain_id, seq, kafka_offset, event_id, ts, agent_id, session_id, tool_name, "
                      "verdict, tier, policy, fail_closed, event, prev_hash, hash) VALUES "
                      "(%s,%s,%s,%s,'2026-11-04T00:00:00Z','attacker','x','execute_sql','allow',1,'sql_analysis',false,%s,%s,%s)",
                      (chain, seq, offset + 1_000_000, eid, ev, bytes(prev_hash), link_hash(bytes(prev_hash), chain, seq, ev)))
        else:
            seq = None
    rep = verify(LAB_DSN_IN_NETWORK)
    kinds = sorted({p["kind"] for p in (rep.get("problems") or [])})
    return {"attack": name, "chain": chain, "seq": seq, "detected": not rep["ok"], "problem_kinds": kinds,
            "problems": len(rep.get("problems") or []), "rows_verified": rep["rows_verified"]}


def main() -> None:
    real = verify()
    print(f"live log: ok={real['ok']} rows={real['rows_verified']} checkpoints={real['checkpoints_verified']} "
          f"kafka-matched={real.get('rows_cross_checked_with_kafka')}")
    ao = append_only_checks()
    print("append-only:", ao)
    control = attack("none")
    print("control copy (no attack):", control)
    results = []
    for name in ("edit_event", "edit_column", "delete_middle", "truncate_tail", "rewrite_chain", "forge_append"):
        r = attack(name)
        results.append(r)
        print(f"{name:14} detected={r['detected']}  {r['problem_kinds']}")
    psql("DROP DATABASE IF EXISTS tamper_lab")
    out = {"live_log": {k: real[k] for k in ("ok", "rows_verified", "checkpoints_verified", "rows_cross_checked_with_kafka")},
           "append_only": ao, "control": control, "attacks": results,
           "all_detected": all(r["detected"] for r in results) and not control["detected"]}
    write_result("tamper", "tamper.json", out)
    if not out["all_detected"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
