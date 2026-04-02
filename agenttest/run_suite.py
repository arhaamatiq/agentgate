#!/usr/bin/env python3
"""AgentGate Agent Task Test Suite — entry point."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if not os.environ.get(key.strip()):
                os.environ[key.strip()] = val.strip()


def load_scenarios(mode: str, domain: str | None = None) -> list[dict]:
    scenarios_dir = Path(__file__).parent / "scenarios"
    all_scenarios: list[dict] = []

    domain_files = [
        "data_ops.json", "file_ops.json", "communications.json", "infrastructure.json",
    ]
    for fname in domain_files:
        if domain and not fname.startswith(domain):
            continue
        path = scenarios_dir / fname
        if path.exists():
            with open(path) as f:
                all_scenarios.extend(json.load(f))

    if mode != "quick":
        traj_dir = scenarios_dir / "trajectories"
        if traj_dir.exists():
            for tf in sorted(traj_dir.glob("*.json")):
                with open(tf) as f:
                    all_scenarios.extend(json.load(f))

    if mode == "quick":
        quick: list[dict] = []
        by_dom: dict[str, list[dict]] = {}
        for s in all_scenarios:
            by_dom.setdefault(s["domain"], []).append(s)
        for dom_scenarios in by_dom.values():
            allows = [s for s in dom_scenarios if s["expected_verdict"] == "ALLOW"][:3]
            blocks = [s for s in dom_scenarios if s["expected_verdict"] == "BLOCK"][:5]
            quick.extend(allows + blocks)
        all_scenarios = quick

    return all_scenarios


async def _run(mode: str, domain: str | None) -> None:
    from agenttest.runner import AgentRunner
    from agenttest.evaluator import HybridEvaluator
    from agenttest.reporter import ReportGenerator

    scenarios = load_scenarios(mode, domain)
    single = [s for s in scenarios if s.get("test_type", "single_turn") == "single_turn"]
    multi = [s for s in scenarios if s.get("test_type") == "multi_turn"]

    print(f"\n{'=' * 60}")
    print("AgentGate Agent Task Test Suite")
    print(f"Mode: {mode} | Single-turn: {len(single)} | Multi-turn: {len(multi)}")
    print(f"{'=' * 60}\n")

    runner = AgentRunner()
    print("── Running scenarios ──")
    raw_results = await runner.run_all(scenarios)

    evaluator = HybridEvaluator()
    print("\n── Evaluating results ──")
    evaluated = await evaluator.evaluate_all(raw_results)

    # Save raw results for debugging
    raw_path = Path(__file__).parent / "reports" / "latest_raw.json"
    with open(raw_path, "w") as f:
        json.dump(
            [_sanitize(r) for r in evaluated],
            f, indent=2, default=str,
        )

    reporter = ReportGenerator()
    report_path = reporter.generate(evaluated, scenarios)
    print(f"\nFull report: {report_path}")


def _sanitize(obj: dict) -> dict:
    """Strip large nested scenario objects for serialization."""
    out = {}
    for k, v in obj.items():
        if k == "scenario":
            out[k] = {"id": v.get("id"), "domain": v.get("domain"),
                       "expected_verdict": v.get("expected_verdict"),
                       "violation_category": v.get("violation_category"),
                       "difficulty": v.get("difficulty")}
        else:
            out[k] = v
    return out


def main() -> None:
    _load_dotenv()

    parser = argparse.ArgumentParser(description="AgentGate Agent Task Test Suite")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--quick", action="store_true", help="~30 scenarios, no trajectories")
    group.add_argument("--full", action="store_true", help="All 180 scenarios")
    group.add_argument(
        "--domain", type=str,
        choices=["data_ops", "file_ops", "communications", "infrastructure"],
    )
    args = parser.parse_args()

    mode = "quick" if args.quick else ("domain" if args.domain else "full")
    asyncio.run(_run(mode, args.domain))


if __name__ == "__main__":
    main()
