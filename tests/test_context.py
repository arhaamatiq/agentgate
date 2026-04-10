"""Tests for context propagation using contextvars."""

from __future__ import annotations

import asyncio

import pytest

from agentgate.context import (
    AgentContext,
    agent_context,
    get_context,
    reset_context,
    set_context,
)


class TestAgentContext:
    """Test the AgentContext dataclass."""

    def test_record_action(self) -> None:
        ctx = AgentContext(agent_id="test")
        ctx.record_action("tool_a", {"x": 1}, "allow")
        ctx.record_action("tool_b", {"y": 2}, "block")

        assert len(ctx.action_history) == 2
        assert ctx.action_history[0]["tool_name"] == "tool_a"
        assert ctx.action_history[1]["verdict"] == "block"

    def test_action_history_maxlen(self) -> None:
        ctx = AgentContext(agent_id="test")
        for i in range(60):
            ctx.record_action(f"tool_{i}", {}, "allow")
        assert len(ctx.action_history) == 50


class TestContextVars:
    """Test context variable propagation."""

    def setup_method(self) -> None:
        reset_context()

    def test_get_context_auto_creates(self) -> None:
        ctx = get_context()
        assert ctx.agent_id.startswith("auto-")

    def test_set_and_get_context(self) -> None:
        ctx = AgentContext(agent_id="my-agent", task_id="task-1")
        set_context(ctx)
        retrieved = get_context()
        assert retrieved.agent_id == "my-agent"
        assert retrieved.task_id == "task-1"

    def test_context_manager_sync(self) -> None:
        with agent_context(agent_id="scoped-agent", task_id="run-1") as ctx:
            assert ctx.agent_id == "scoped-agent"
            current = get_context()
            assert current.agent_id == "scoped-agent"

        new_ctx = get_context()
        assert new_ctx.agent_id != "scoped-agent"

    @pytest.mark.asyncio
    async def test_context_manager_async(self) -> None:
        async with agent_context(agent_id="async-agent") as ctx:
            assert ctx.agent_id == "async-agent"
            current = get_context()
            assert current.agent_id == "async-agent"

    @pytest.mark.asyncio
    async def test_context_isolation_across_tasks(self) -> None:
        """Contexts should be isolated between concurrent async tasks."""
        results: dict[str, str] = {}

        async def task_a() -> None:
            with agent_context(agent_id="agent-a"):
                await asyncio.sleep(0.01)
                results["a"] = get_context().agent_id

        async def task_b() -> None:
            with agent_context(agent_id="agent-b"):
                await asyncio.sleep(0.01)
                results["b"] = get_context().agent_id

        await asyncio.gather(task_a(), task_b())
        assert results["a"] == "agent-a"
        assert results["b"] == "agent-b"
