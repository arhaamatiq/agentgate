"""Tests for the two-tier policy evaluation engine."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentgate.context import agent_context, reset_context
from agentgate.engine import PolicyEngine, _classify_action
from agentgate.models import (
    ActionType,
    ScopePolicy,
    Severity,
    ToolCall,
    VerdictType,
)


class TestActionClassification:
    """Test automatic action type inference from tool names and arguments."""

    def test_sql_by_name(self) -> None:
        tc = ToolCall(tool_name="execute_sql", arguments={"query": "SELECT 1"})
        assert _classify_action(tc) == ActionType.SQL

    def test_sql_by_args(self) -> None:
        tc = ToolCall(tool_name="custom_tool", arguments={"input": "select * from users"})
        assert _classify_action(tc) == ActionType.SQL

    def test_filesystem_by_name(self) -> None:
        tc = ToolCall(tool_name="read_file", arguments={"path": "/tmp/data.csv"})
        assert _classify_action(tc) == ActionType.FILESYSTEM

    def test_http_by_name(self) -> None:
        tc = ToolCall(tool_name="http_request", arguments={"url": "https://example.com"})
        assert _classify_action(tc) == ActionType.HTTP

    def test_http_by_args(self) -> None:
        tc = ToolCall(tool_name="call_api", arguments={"target": "https://example.com/api"})
        assert _classify_action(tc) == ActionType.HTTP

    def test_shell_by_name(self) -> None:
        tc = ToolCall(tool_name="execute_command", arguments={"cmd": "ls -la"})
        assert _classify_action(tc) == ActionType.SHELL

    def test_unknown_fallback(self) -> None:
        tc = ToolCall(tool_name="custom_tool", arguments={"data": 42})
        assert _classify_action(tc) == ActionType.UNKNOWN


class TestPolicyEngineTier1:
    """Test Tier 1 — synchronous static analysis."""

    def setup_method(self) -> None:
        self.engine = PolicyEngine()
        reset_context()

    def test_safe_sql_allowed(self) -> None:
        tc = ToolCall(tool_name="query_db", arguments={"query": "SELECT * FROM users"})
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.ALLOW
        assert verdict.tier_used == 1

    def test_destructive_sql_blocked(self) -> None:
        tc = ToolCall(tool_name="query_db", arguments={"query": "DROP TABLE users"})
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.BLOCK
        assert verdict.tier_used == 1
        assert verdict.severity == Severity.CRITICAL

    def test_path_traversal_blocked(self) -> None:
        tc = ToolCall(tool_name="read_file", arguments={"path": "../../etc/passwd"})
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.BLOCK

    def test_ssrf_blocked(self) -> None:
        tc = ToolCall(
            tool_name="http_request",
            arguments={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.BLOCK
        assert verdict.severity == Severity.CRITICAL

    def test_shell_always_escalates(self) -> None:
        tc = ToolCall(tool_name="run_command", arguments={"cmd": "echo hello"})
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.ESCALATE

    def test_unknown_tool_escalates(self) -> None:
        tc = ToolCall(tool_name="mystery_tool", arguments={"x": 1})
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.ESCALATE


class TestScopePolicy:
    """Test scope-based policy enforcement."""

    def setup_method(self) -> None:
        self.scope = ScopePolicy(
            task="Generate sales report",
            allowed_operations=["read", "aggregate", "write"],
            allowed_resources=["sales_data", "reports"],
        )
        self.engine = PolicyEngine(scope=self.scope)
        reset_context()

    def test_allowed_operation_passes(self) -> None:
        tc = ToolCall(
            tool_name="query_db",
            arguments={"query": "SELECT * FROM sales_data"},
        )
        verdict = self.engine.evaluate(tc)
        assert verdict.action != VerdictType.BLOCK or verdict.policy_name != "scope_operation"

    def test_destructive_blocked_by_scope_and_analyzer(self) -> None:
        tc = ToolCall(
            tool_name="query_db",
            arguments={"query": "DROP TABLE sales_data"},
        )
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.BLOCK

    def test_denied_resource_blocked(self) -> None:
        tc = ToolCall(
            tool_name="read_file",
            arguments={"path": "secret_data/passwords.txt", "resource": "secret_data"},
        )
        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.BLOCK
        assert verdict.policy_name == "scope_resource"


class TestRateLimiting:
    """Test the sliding-window rate limiter."""

    def setup_method(self) -> None:
        self.engine = PolicyEngine(rate_limit=5, rate_window=60.0)
        reset_context()

    def test_rate_limit_blocks_after_threshold(self) -> None:
        tc = ToolCall(
            tool_name="query_db",
            arguments={"query": "SELECT 1"},
        )
        for _ in range(5):
            verdict = self.engine.evaluate(tc)
            assert verdict.action != VerdictType.BLOCK or verdict.policy_name == "rate_limit"

        verdict = self.engine.evaluate(tc)
        assert verdict.action == VerdictType.BLOCK
        assert verdict.policy_name == "rate_limit"


class TestPolicyEngineTier2:
    """Test Tier 2 — async LLM-as-judge evaluation."""

    @pytest.mark.asyncio
    async def test_tier2_blocks_on_inconsistent(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "consistent": False,
            "confidence": 0.9,
            "reversible": False,
            "reasoning": "Action is not consistent with stated task",
        })
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        engine = PolicyEngine(openai_client=mock_client)

        with agent_context(agent_id="test", task_description="Write a report"):
            tc = ToolCall(tool_name="run_command", arguments={"cmd": "rm -rf /"})
            verdict = await engine.evaluate_async(tc)

        assert verdict.action == VerdictType.BLOCK
        assert verdict.tier_used == 2

    @pytest.mark.asyncio
    async def test_tier2_allows_consistent_action(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "consistent": True,
            "confidence": 0.95,
            "reversible": True,
            "reasoning": "Action is consistent with task",
        })
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        engine = PolicyEngine(openai_client=mock_client)

        with agent_context(agent_id="test", task_description="List files"):
            tc = ToolCall(tool_name="run_command", arguments={"cmd": "ls -la"})
            verdict = await engine.evaluate_async(tc)

        assert verdict.action == VerdictType.ALLOW
        assert verdict.tier_used == 2

    @pytest.mark.asyncio
    async def test_tier2_blocks_on_low_confidence(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "consistent": False,
            "confidence": 0.3,
            "reversible": True,
            "reasoning": "Uncertain about this action",
        })
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        engine = PolicyEngine(openai_client=mock_client)

        with agent_context(agent_id="test", task_description="Analyze data"):
            tc = ToolCall(tool_name="run_command", arguments={"cmd": "curl something"})
            verdict = await engine.evaluate_async(tc)

        assert verdict.action == VerdictType.BLOCK
        assert verdict.tier_used == 2

    @pytest.mark.asyncio
    async def test_tier2_unavailable_blocks(self) -> None:
        """When Tier 2 is unavailable, ambiguous actions are blocked (never fail open)."""
        engine = PolicyEngine(openai_client=None)

        tc = ToolCall(tool_name="run_command", arguments={"cmd": "echo test"})
        verdict = await engine.evaluate_async(tc)

        assert verdict.action == VerdictType.BLOCK
        assert "unavailable" in verdict.reasoning.lower()

    @pytest.mark.asyncio
    async def test_tier2_api_error_blocks(self) -> None:
        """When Tier 2 API call fails, default to block."""
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=Exception("API error")
        )

        engine = PolicyEngine(openai_client=mock_client)

        with agent_context(agent_id="test", task_description="Test"):
            tc = ToolCall(tool_name="run_command", arguments={"cmd": "test"})
            verdict = await engine.evaluate_async(tc)

        assert verdict.action == VerdictType.BLOCK
        assert verdict.tier_used == 2
