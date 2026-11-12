#!/usr/bin/env python3
"""Score the in-process Python engine (the reference) on a frozen set.

Separates "did the gateway change any decision?" from "did the LLM judge
drift since run 007?":

  --judge replay:<cassette>   answer every judge prompt from a cassette the
                              gateway recorded. Each prompt the Python engine
                              builds must hash to an entry in the cassette
                              (byte-identical prompts), and the verdicts must
                              then match the gateway's exactly.
  --judge live                call the judge model now, in-process, the way
                              run 007 did.

    python bench/accuracy/run_python_reference.py --judge replay:bench/cassettes/dev_live_r1.jsonl
    python bench/accuracy/run_python_reference.py --judge live
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agentgate.context import agent_context, reset_context  # noqa: E402
from agentgate.engine import PolicyEngine  # noqa: E402
from agentgate.judge_service.server import Cassette  # noqa: E402
from agentgate.models import ScopePolicy, ToolCall  # noqa: E402
from bench.accuracy.run_accuracy import SETS, metrics  # noqa: E402


class ReplayClient:
    """Stands in for AsyncOpenAI: serves recorded responses by prompt digest."""

    def __init__(self, path: str) -> None:
        self.cassette = Cassette(path, "replay")
        self.hits = self.misses = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **request):
        key = Cassette.key(request)
        if key not in self.cassette.entries:
            self.misses += 1
            raise LookupError("prompt not in cassette")
        self.hits += 1
        msg = SimpleNamespace(content=self.cassette.entries[key])
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


async def run_case(engine: PolicyEngine, case: dict, sem: asyncio.Semaphore) -> list[dict]:
    async with sem:
        reset_context()
        out = []
        engine_scope = ScopePolicy(task=case["task"], **case["scope"])
        async with agent_context(agent_id=case["case_id"], task_description=case["task"]) as ctx:
            for i, step in enumerate(case["steps"]):
                engine.set_scope(engine_scope)
                tc = ToolCall(tool_name=step["tool_name"], arguments=step["arguments"])
                v = await engine.evaluate_async(tc)
                ctx.record_action(tc.tool_name, tc.arguments, v.action.value)
                out.append({"case_id": case["case_id"], "step": i + 1, "label": step["label"],
                            "verdict": v.action.value, "tier": v.tier_used, "policy": v.policy_name,
                            "run007_verdict": step.get("run007_verdict")})
        return out


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", choices=SETS, default="dev")
    ap.add_argument("--judge", required=True, help="live | replay:<cassette path>")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    if args.judge == "live":
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
        replay = None
    else:
        replay = ReplayClient(args.judge.split(":", 1)[1])
        client = replay
    # The engine is shared but stateless per call; scope is set per step and
    # cases run one at a time per engine to keep scope assignment race-free.
    cases = [json.loads(line) for line in SETS[args.set].read_text().splitlines() if line.strip()]
    rows: list[dict] = []
    sem = asyncio.Semaphore(1)
    engines = [PolicyEngine(openai_client=client, tier2_model="gpt-4o-mini", rate_limit=10**9) for _ in range(8)]

    async def worker(idx: int) -> None:
        for case in cases[idx::len(engines)]:
            rows.extend(await run_case(engines[idx], case, asyncio.Semaphore(1)))

    await asyncio.gather(*(worker(i) for i in range(len(engines))))
    del sem
    label = args.label or f"python_reference_{args.set}_{'live' if replay is None else 'replay'}"
    summary = {"label": label, "set": args.set, "engine": "in-process Python PolicyEngine",
               "judge": args.judge, "decisions": len(rows), "metrics": metrics(rows)}
    if replay is not None:
        summary["prompt_matches"] = replay.hits
        summary["prompt_misses"] = replay.misses
        gw = Path(args.judge.split(":", 1)[1]).stem
        gw_rows = {(r["case_id"], r["step"]): r["verdict"] for r in map(json.loads, (ROOT / "bench/results/accuracy" / f"{gw}.decisions.jsonl").read_text().splitlines())}
        summary["verdicts_differing_from_gateway"] = sum(1 for r in rows if gw_rows.get((r["case_id"], r["step"])) != r["verdict"])
    if args.set == "dev":
        summary["gateway_vs_python_note"] = "compare with bench/results/accuracy/<gateway run>.json"
    out = ROOT / "bench/results/accuracy" / f"{label}.json"
    out.write_text(json.dumps(summary, indent=2) + "\n")
    m = summary["metrics"]
    print(json.dumps({k: v for k, v in summary.items() if k != "metrics"}))
    print(f"recall {m['recall']:.1%}  precision {m['precision']:.1%}  FP rate {m['fp_rate']:.1%}  "
          f"(TP {m['TP']} FN {m['FN']} FP {m['FP']} TN {m['TN']})")


if __name__ == "__main__":
    asyncio.run(main())
