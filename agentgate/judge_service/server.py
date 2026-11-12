"""gRPC server for AgentGate's Tier 2 LLM judge.

The Go gateway resolves every call it can with deterministic rules and sends
only ambiguous ones here. This service builds the same judge prompt the
in-process engine builds (agentgate.engine.build_judge_prompt), calls an
OpenAI-compatible model, and applies the same decision thresholds
(interpret_judge_response). Every failure inside the judge becomes BLOCK, and
the gateway separately treats any RPC error or timeout as BLOCK.

Configuration (environment):
  AGENTGATE_JUDGE_PORT          gRPC port (default 50051)
  AGENTGATE_JUDGE_MODEL         model name (default gpt-4o-mini)
  AGENTGATE_JUDGE_API_KEY       falls back to OPENAI_API_KEY
  AGENTGATE_JUDGE_BASE_URL      any OpenAI-compatible endpoint
  AGENTGATE_JUDGE_CASSETTE      path to a JSONL record/replay file
  AGENTGATE_JUDGE_CASSETTE_MODE "record", "replay" or "extend"
  AGENTGATE_JUDGE_CONCURRENCY   max in-flight model calls (default 32)

Cassettes make benchmarks reproducible without an API key: a "record" run
stores the model's raw response for each prompt, and a "replay" run serves
those responses. A prompt missing from the cassette fails closed. An "extend"
run serves recorded prompts from the cassette and calls the model (and
records) only for new ones, so a before/after comparison differs only where
the rules changed what reaches the judge.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from agentgate.engine import (
    build_judge_prompt,
    interpret_judge_response,
    judge_request,
    tier2_block,
)
from agentgate.judge_service.gen import judge_pb2, judge_pb2_grpc
from agentgate.models import ScopePolicy, Verdict, VerdictType

logger = logging.getLogger("agentgate.judge")


class CassetteMiss(Exception):
    pass


class Cassette:
    """Append-only JSONL map from prompt digest to raw model response."""

    def __init__(self, path: str, mode: str) -> None:
        if mode not in ("record", "replay", "extend"):
            raise ValueError("cassette mode must be 'record', 'replay' or 'extend'")
        self.path = Path(path)
        self.mode = mode
        self.entries: dict[str, str | None] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    row = json.loads(line)
                    self.entries[row["key"]] = row["content"]
        self._lock = asyncio.Lock()

    @staticmethod
    def key(request: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()

    def get(self, key: str) -> str | None:
        if key not in self.entries:
            raise CassetteMiss(key)
        return self.entries[key]

    async def put(self, key: str, content: str | None) -> None:
        async with self._lock:
            if key in self.entries:
                return
            self.entries[key] = content
            with self.path.open("a") as f:
                f.write(json.dumps({"key": key, "content": content}) + "\n")


class JudgeServicer(judge_pb2_grpc.JudgeServicer):
    def __init__(self, client: Any, model: str, cassette: Cassette | None, concurrency: int) -> None:
        self._client = client
        self._model = model
        self._cassette = cassette
        self._sem = asyncio.Semaphore(concurrency)

    async def _complete(self, user_prompt: str) -> str | None:
        request = judge_request(self._model, user_prompt)
        key = Cassette.key(request)
        if self._cassette and self._cassette.mode == "replay":
            return self._cassette.get(key)
        if self._cassette and self._cassette.mode == "extend" and key in self._cassette.entries:
            return self._cassette.entries[key]
        if self._client is None:
            raise RuntimeError("no judge API key configured")
        async with self._sem:
            response = await self._client.chat.completions.create(**request)
        content = response.choices[0].message.content
        if self._cassette:
            await self._cassette.put(key, content)
        return content

    async def Evaluate(self, request: judge_pb2.EvaluateRequest, context: Any) -> judge_pb2.EvaluateResponse:
        started = time.perf_counter()
        try:
            scope = None
            if request.HasField("scope"):
                scope = ScopePolicy(
                    task=request.scope.task,
                    allowed_operations=list(request.scope.allowed_operations),
                    allowed_resources=list(request.scope.allowed_resources),
                    deny_operations=list(request.scope.deny_operations),
                )
            prompt = build_judge_prompt(
                tool_name=request.tool_name,
                arguments=json.loads(request.arguments_json or "{}"),
                action_type=request.action_type,
                operation=request.operation,
                scope=scope,
                task_description=request.task,
                agent_id=request.agent_id,
                user_id=request.user_id,
                history=[
                    {
                        "tool_name": h.tool_name,
                        "arguments": json.loads(h.arguments_json or "{}"),
                        "verdict": h.verdict,
                    }
                    for h in request.history
                ],
                tier1_reasoning=request.tier1_reasoning,
            )
            verdict = interpret_judge_response(await self._complete(prompt))
        except CassetteMiss:
            verdict = tier2_block("Judge cassette has no response for this prompt — blocking by default")
        except Exception as e:  # never let a judge failure become an allow
            logger.error("judge evaluation failed: %s", e)
            verdict = tier2_block(f"Tier 2 evaluation failed ({type(e).__name__}) — blocking by default")
        return _to_proto(verdict, self._model, started)


def _to_proto(v: Verdict, model: str, started: float) -> judge_pb2.EvaluateResponse:
    return judge_pb2.EvaluateResponse(
        verdict=judge_pb2.VERDICT_ALLOW if v.action == VerdictType.ALLOW else judge_pb2.VERDICT_BLOCK,
        confidence=v.confidence,
        reasoning=v.reasoning,
        reversible=v.reversible,
        policy_name=v.policy_name,
        severity=v.severity.value,
        model=model,
        latency_ms=int((time.perf_counter() - started) * 1000),
    )


def _client() -> Any:
    key = os.environ.get("AGENTGATE_JUDGE_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    from openai import AsyncOpenAI

    kwargs: dict[str, Any] = {"api_key": key, "max_retries": 2, "timeout": 30.0}
    if base := os.environ.get("AGENTGATE_JUDGE_BASE_URL"):
        kwargs["base_url"] = base
    return AsyncOpenAI(**kwargs)


async def serve(port: int) -> None:
    model = os.environ.get("AGENTGATE_JUDGE_MODEL", "gpt-4o-mini")
    cassette = None
    if path := os.environ.get("AGENTGATE_JUDGE_CASSETTE"):
        cassette = Cassette(path, os.environ.get("AGENTGATE_JUDGE_CASSETTE_MODE", "replay"))
    client = _client()
    if client is None and not (cassette and cassette.mode == "replay"):
        logger.warning("no judge API key: every escalated call will be BLOCKED (fail-closed)")

    server = grpc.aio.server(options=[("grpc.max_receive_message_length", 8 << 20)])
    judge_pb2_grpc.add_JudgeServicer_to_server(
        JudgeServicer(client, model, cassette, int(os.environ.get("AGENTGATE_JUDGE_CONCURRENCY", "32"))),
        server,
    )
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    await health_servicer.set("agentgate.judge.v1.Judge", health_pb2.HealthCheckResponse.SERVING)
    server.add_insecure_port(f"[::]:{port}")
    await server.start()
    mode = f"cassette={cassette.mode}:{cassette.path}" if cassette else "live"
    logger.info("agentgate judge listening on :%d (model=%s, %s)", port, model, mode)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    await health_servicer.enter_graceful_shutdown()
    await server.stop(grace=5)


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentGate Tier 2 judge (gRPC)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENTGATE_JUDGE_PORT", "50051")))
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("AGENTGATE_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(serve(args.port))


if __name__ == "__main__":
    main()
