#!/usr/bin/env python3
"""Freeze the development benchmark into a replayable dataset.

Run 007 (agenttest/reports/run_007_raw.json) contains every tool call that
GPT-4o-mini generated for the 180 adversarial scenarios, plus the ground-truth
label the hybrid evaluator assigned to each one. Re-generating tool calls on
every run makes results drift with the generator, so the gateway benchmark
replays these exact calls instead.

Output: bench/data/dev_set.jsonl, one line per test run (370 lines):
  - 340 single-turn runs (BLOCK scenarios were sampled 3x, ALLOW scenarios 1x)
  - 30 multi-turn trajectories (126 steps)
for 466 labeled decisions in total.

Agent IDs are replaced with opaque case IDs. The original runner named agents
after the scenario (e.g. "test-data_block_15"), and that name reached the LLM
judge's prompt, which leaks the expected label. See bench/README.md.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "agenttest" / "reports" / "run_007_raw.json"
SCENARIOS = ROOT / "agenttest" / "scenarios"
OUT = ROOT / "bench" / "data" / "dev_set.jsonl"


def load_scenarios() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in sorted(SCENARIOS.glob("*.json")) + sorted((SCENARIOS / "trajectories").glob("*.json")):
        for s in json.loads(f.read_text()):
            out[s["id"]] = s
    return out


def main() -> None:
    scenarios = load_scenarios()
    raw = json.loads(RAW.read_text())
    lines: list[str] = []
    n_steps = 0
    for i, r in enumerate(raw):
        sid = r["scenario"]["id"]
        s = scenarios[sid]
        if r.get("test_type") == "multi_turn":
            steps = [
                {
                    "tool_name": st["tool_call"]["tool_name"],
                    "arguments": st["tool_call"]["arguments"],
                    "label": st["ground_truth"],
                    "run007_verdict": st["firewall_verdict"]["verdict"],
                }
                for st in r["steps"]
            ]
            kind = "trajectory"
        else:
            tc = r["generated_tool_call"]
            steps = [{
                "tool_name": tc["tool_name"],
                "arguments": tc["arguments"],
                "label": r["ground_truth"],
                "run007_verdict": r["firewall_verdict"]["verdict"],
            }]
            kind = "single_turn"
        n_steps += len(steps)
        case_id = "dev-" + hashlib.sha256(f"{i}:{sid}".encode()).hexdigest()[:10]
        lines.append(json.dumps({
            "case_id": case_id,
            "kind": kind,
            "scenario_id": sid,
            "run_idx": r.get("run_idx", 1),
            "domain": s["domain"],
            "category": s.get("violation_category", "none"),
            "difficulty": s.get("difficulty", ""),
            "expected_verdict": s["expected_verdict"],
            "task": s["task"],
            "scope": s.get("scope", {}),
            "steps": steps,
        }))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} cases / {n_steps} decisions -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
