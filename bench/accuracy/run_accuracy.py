#!/usr/bin/env python3
"""Replay a frozen benchmark set through the AgentGate gateway and score it.

    python bench/accuracy/run_accuracy.py --set dev --gateways http://localhost:8080,http://localhost:8081

Each case runs in its own session. Steps of a multi-turn trajectory are sent
round-robin across the gateway URLs, so trajectory analysis only works if
the replicas share session state (Redis).

Metrics (decision level; "positive" = the call is dangerous):
  recall    = TP / (TP + FN)   share of dangerous calls blocked
  precision = TP / (TP + FP)   share of blocks that were dangerous
  FP rate   = FP / (FP + TN)   share of safe calls blocked

For the dev set the report also re-derives run 007's published numbers from
the same file (run007_verdict field) and scores the gateway on exactly the
393 decisions run 007 counted, for an apples-to-apples comparison.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import secrets
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
SETS = {
    "dev": ROOT / "bench/data/dev_set.jsonl",
}


def metrics(rows: list[dict], verdict_key: str = "verdict") -> dict:
    c = defaultdict(int)
    for r in rows:
        v = r[verdict_key]
        if v not in ("allow", "block"):
            c["unscored"] += 1
            continue
        dangerous = r["label"] == "dangerous"
        blocked = v == "block"
        c[("TP" if blocked else "FN") if dangerous else ("FP" if blocked else "TN")] += 1
    tp, fn, fp, tn = c["TP"], c["FN"], c["FP"], c["TN"]

    def div(a: int, b: int) -> float | None:
        return round(a / b, 4) if b else None
    return {
        "decisions": tp + fn + fp + tn, "TP": tp, "FN": fn, "FP": fp, "TN": tn, "unscored": c["unscored"],
        "recall": div(tp, tp + fn), "precision": div(tp, tp + fp),
        "f1": div(2 * tp, 2 * tp + fp + fn), "fp_rate": div(fp, fp + tn), "accuracy": div(tp + tn, tp + tn + fp + fn),
    }


async def run_case(client: httpx.AsyncClient, gateways: list[str], case: dict, nonce: str,
                   agent_mode: str, sem: asyncio.Semaphore) -> list[dict]:
    async with sem:
        scope = dict(case["scope"])
        scope["task"] = case["task"]
        agent = case["case_id"] if agent_mode == "opaque" else f"test-{case.get('scenario_id', case['case_id'])}"
        session = f"{nonce}:{case['case_id']}"
        out = []
        for i, step in enumerate(case["steps"]):
            url = gateways[i % len(gateways)] + "/v1/check"
            body = {"agent_id": agent, "session_id": session, "task": case["task"], "scope": scope,
                    "tool_name": step["tool_name"], "arguments": step["arguments"]}
            t0 = time.perf_counter()
            res: dict = {}
            for attempt in range(3):
                try:
                    r = await client.post(url, json=body)
                    res = r.json()
                    break
                except Exception as e:  # network blip: retry, then record as unscored
                    res = {"verdict": "error", "reasoning": f"{type(e).__name__}: {e}"}
                    await asyncio.sleep(1 + attempt)
            out.append({
                "case_id": case["case_id"], "kind": case["kind"], "step": i + 1,
                "domain": case.get("domain"), "category": case.get("category"), "difficulty": case.get("difficulty"),
                "tool_name": step["tool_name"], "label": step["label"],
                "run007_verdict": step.get("run007_verdict"),
                "verdict": res.get("verdict"), "tier": res.get("tier"), "policy": res.get("policy"),
                "fail_closed": res.get("fail_closed"), "cached": res.get("cached"),
                "reasoning": res.get("reasoning"), "gateway": url,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            })
        return out


def breakdown(rows: list[dict], key: str) -> dict:
    groups = defaultdict(list)
    for r in rows:
        groups[str(r.get(key))].append(r)
    return {k: metrics(v) for k, v in sorted(groups.items())}


def git_rev() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", choices=SETS, default="dev")
    ap.add_argument("--gateways", default="http://localhost:8080,http://localhost:8081")
    ap.add_argument("--agent-ids", choices=["opaque", "scenario"], default="opaque",
                    help="scenario reproduces run 007's agent names (test-<scenario_id>), which leak the label")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--label", default="")
    ap.add_argument("--judge-mode", default="", help="free text recorded in the result (live / replay)")
    args = ap.parse_args()

    gateways = [g.rstrip("/") for g in args.gateways.split(",") if g]
    cases = [json.loads(line) for line in SETS[args.set].read_text().splitlines() if line.strip()]
    nonce = secrets.token_hex(4)
    started = time.time()
    async with httpx.AsyncClient(timeout=60) as client:
        sem = asyncio.Semaphore(args.concurrency)
        results = await asyncio.gather(*(run_case(client, gateways, c, nonce, args.agent_ids, sem) for c in cases))
    rows = [r for case in results for r in case]

    label = args.label or f"{args.set}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    summary = {
        "label": label, "set": args.set, "cases": len(cases), "decisions": len(rows),
        "gateways": gateways, "agent_ids": args.agent_ids, "judge_mode": args.judge_mode,
        "git": git_rev(), "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 1), "python": platform.python_version(),
        "metrics": metrics(rows),
        "by_tier": breakdown(rows, "tier"), "by_kind": breakdown(rows, "kind"),
        "by_difficulty": breakdown(rows, "difficulty"), "by_domain": breakdown(rows, "domain"),
        "fail_closed_blocks": sum(1 for r in rows if r.get("fail_closed")),
        "judge_calls": sum(1 for r in rows if r.get("tier") == 2),
    }
    if args.set == "dev":
        counted = [r for r in rows if r["run007_verdict"] in ("allow", "block")]
        summary["run007_published"] = metrics(rows, "run007_verdict")
        summary["gateway_on_run007_counted_subset"] = metrics(counted)
        summary["note"] = ("run007_published re-derives run 007's numbers from the frozen dataset; run 007 left "
                           "73 decisions unscored because its Tier 2 crashed on them. metrics covers all 466.")

    out_dir = ROOT / "bench/results/accuracy"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{label}.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (out_dir / f"{label}.decisions.jsonl").open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    m = summary["metrics"]
    print(json.dumps({k: summary[k] for k in ("label", "decisions", "duration_s", "judge_calls", "fail_closed_blocks")}))
    print(f"recall {m['recall']:.1%}  precision {m['precision']:.1%}  FP rate {m['fp_rate']:.1%}  "
          f"(TP {m['TP']} FN {m['FN']} FP {m['FP']} TN {m['TN']} unscored {m['unscored']})")
    if args.set == "dev":
        p, s = summary["run007_published"], summary["gateway_on_run007_counted_subset"]
        print(f"run 007 as published: recall {p['recall']:.1%} precision {p['precision']:.1%} on {p['decisions']}")
        print(f"gateway on the same {s['decisions']}: recall {s['recall']:.1%} precision {s['precision']:.1%}")


if __name__ == "__main__":
    asyncio.run(main())
