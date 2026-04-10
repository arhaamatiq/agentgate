"""Timing tests to verify async logging adds < 5ms to the critical path.

This is a hard requirement: audit logging must be fire-and-forget.
"""

from __future__ import annotations

import time

import pytest

from agentgate.context import AgentContext, agent_context, reset_context
from agentgate.engine import PolicyEngine
from agentgate.logger import AuditLogger, log_action_fire_and_forget
from agentgate.models import Severity, ToolCall, Verdict, VerdictType


class TestLoggingOverhead:
    """Verify that fire-and-forget logging adds negligible latency."""

    def setup_method(self) -> None:
        reset_context()
        AuditLogger._instance = None

    def test_sync_logging_under_5ms(self) -> None:
        """Fire-and-forget logging in sync context must add < 5ms."""
        tc = ToolCall(tool_name="test_tool", arguments={"key": "value"})
        verdict = Verdict(
            action=VerdictType.ALLOW,
            tier_used=1,
            policy_name="test",
            severity=Severity.LOW,
            reasoning="test",
        )
        ctx = AgentContext(agent_id="timing-test")

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            log_action_fire_and_forget(tc, verdict, ctx)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 5.0, f"Average logging overhead {avg_ms:.2f}ms exceeds 5ms threshold"

    @pytest.mark.asyncio
    async def test_async_logging_under_5ms(self) -> None:
        """Fire-and-forget logging in async context must add < 5ms."""
        tc = ToolCall(tool_name="test_tool", arguments={"key": "value"})
        verdict = Verdict(
            action=VerdictType.ALLOW,
            tier_used=1,
            policy_name="test",
            severity=Severity.LOW,
            reasoning="test",
        )

        async with agent_context(agent_id="async-timing-test") as ctx:
            iterations = 100
            start = time.perf_counter()
            for _ in range(iterations):
                log_action_fire_and_forget(tc, verdict, ctx)
            elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 5.0, f"Average logging overhead {avg_ms:.2f}ms exceeds 5ms threshold"

    def test_tier1_evaluation_under_2ms(self) -> None:
        """Tier 1 static analysis should complete in < 2ms for simple cases."""
        engine = PolicyEngine()
        tc = ToolCall(
            tool_name="query_db",
            arguments={"query": "SELECT * FROM users"},
        )

        # Warm up
        engine.evaluate(tc)

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            engine.evaluate(tc)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 2.0, f"Average Tier 1 evaluation {avg_ms:.2f}ms exceeds 2ms threshold"
