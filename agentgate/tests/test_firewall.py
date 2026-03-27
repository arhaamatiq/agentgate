"""Tests for the firewall public API — protect_all(), scope(), guard()."""

from __future__ import annotations

import pytest

from agentgate.lib.context import reset_context
from agentgate.lib.firewall import (
    FirewallBlockedError,
    get_engine,
    guard,
    scope,
)


class TestGuardDecorator:
    """Test the @guard decorator for raw Python functions."""

    def setup_method(self) -> None:
        reset_context()
        import agentgate.lib.firewall as fw
        fw._engine = None

    def test_guard_allows_safe_function(self) -> None:
        @guard
        def read_data(query: str = "") -> str:
            return f"result: {query}"

        result = read_data(query="SELECT 1")
        assert result == "result: SELECT 1"

    def test_guard_blocks_dangerous_sql(self) -> None:
        @guard(tool_name="execute_sql")
        def run_sql(query: str = "") -> str:
            return "executed"

        with pytest.raises(FirewallBlockedError) as exc_info:
            run_sql(query="DROP TABLE users")

        assert "BLOCKED" in str(exc_info.value)

    def test_guard_blocks_path_traversal(self) -> None:
        @guard(tool_name="read_file")
        def read_file(path: str = "") -> str:
            return "contents"

        with pytest.raises(FirewallBlockedError):
            read_file(path="../../etc/passwd")

    @pytest.mark.asyncio
    async def test_guard_async_function(self) -> None:
        @guard(tool_name="async_query")
        async def async_query(query: str = "") -> str:
            return f"async: {query}"

        result = await async_query(query="SELECT 1")
        assert result == "async: SELECT 1"

    @pytest.mark.asyncio
    async def test_guard_async_blocks_dangerous(self) -> None:
        @guard(tool_name="async_sql")
        async def async_sql(query: str = "") -> str:
            return "done"

        with pytest.raises(FirewallBlockedError):
            await async_sql(query="DROP TABLE users")


class TestScope:
    """Test the scope context manager."""

    def setup_method(self) -> None:
        reset_context()
        import agentgate.lib.firewall as fw
        fw._engine = None

    def test_scope_sets_policy(self) -> None:
        with scope(
            task="Test task",
            allowed_operations=["read"],
            allowed_resources=["test_data"],
        ) as engine:
            assert engine.scope is not None
            assert engine.scope.task == "Test task"
            assert "read" in engine.scope.allowed_operations

        current_engine = get_engine()
        assert current_engine.scope is None

    def test_scope_blocks_disallowed_resource(self) -> None:
        @guard(tool_name="read_file")
        def read_file(path: str = "", resource: str = "") -> str:
            return "contents"

        with scope(
            task="Read reports",
            allowed_operations=["read"],
            allowed_resources=["reports"],
        ):
            with pytest.raises(FirewallBlockedError):
                read_file(path="secret.txt", resource="secrets")
