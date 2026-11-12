"""Tests for the two-tier policy evaluation engine."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentgate.context import agent_context, reset_context
from agentgate.engine import PolicyEngine, _classify_action, build_judge_prompt
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


class TestToolVerbScopes:
    """A declared verb ('delete', 'list', 'restart') authorizes the tool it names, and nothing broader."""

    @staticmethod
    def evaluate(ops: list[str], tool: str, args: dict, deny: list[str] | None = None) -> tuple[str, str]:
        reset_context()
        engine = PolicyEngine(scope=ScopePolicy(
            task="t", allowed_operations=ops, allowed_resources=[], deny_operations=deny or [],
        ))
        v = engine.evaluate(ToolCall(tool_name=tool, arguments=args))
        return v.action.value, v.policy_name

    @pytest.mark.parametrize("ops,tool,args", [
        (["delete"], "delete_file", {"path": "/tmp/old.tmp"}),
        (["delete"], "deleteFile", {"path": "/tmp/old.tmp"}),
        (["list"], "list_directory", {"path": "/mnt/shared"}),
        (["search"], "search_files", {"pattern": "*.pdf", "path": "/srv/reports"}),
        (["restart"], "restart_service", {"service": "api"}),
        (["forward"], "forward_message", {"message_id": "m1", "to": "team@company.com"}),
        (["export"], "export_data", {"query": "SELECT * FROM orders", "destination": "s3://reports"}),
    ])
    def test_verb_authorizes_the_tool_it_names(self, ops: list[str], tool: str, args: dict) -> None:
        assert self.evaluate(ops, tool, args)[1] != "scope_operation"

    @pytest.mark.parametrize("ops,tool,args", [
        (["delete"], "write_file", {"path": "/tmp/x", "content": "x"}),         # different verb
        (["delete"], "execute_sql", {"query": "DROP TABLE users"}),             # verb is 'execute'
        (["delete"], "delete_records", {"query": "DROP TABLE users"}),          # class 'destructive'
        (["list"], "list_and_delete_files", {"path": "/mnt/shared"}),           # class 'write'
        (["export"], "export_data", {"query": "DELETE FROM orders", "destination": "s3://x"}),
        (["fetch"], "fetch_url", {"url": "https://example.com"}),               # class 'http'
        (["run"], "run_command", {"cmd": "ls"}),                                # no verb for 'execute'
    ])
    def test_verb_never_authorizes_a_broader_class(self, ops: list[str], tool: str, args: dict) -> None:
        assert self.evaluate(ops, tool, args) == ("block", "scope_operation")

    def test_denied_verb_blocks_even_when_class_is_allowed(self) -> None:
        assert self.evaluate(["write"], "delete_file", {"path": "/tmp/x"}, deny=["delete"]) == (
            "block", "scope_operation")

    def test_judge_prompt_says_why_the_operation_passed(self) -> None:
        scope = ScopePolicy(task="t", allowed_operations=["restart"])
        prompt = build_judge_prompt(tool_name="restart_service", arguments={"service": "api"},
                                    action_type="unknown", operation="deploy", scope=scope)
        assert "YES — permitted (declared as 'restart', the verb of tool 'restart_service')" in prompt
        # Calls the older layers already allowed keep their prompt unchanged.
        scope = ScopePolicy(task="t", allowed_operations=["execute"])
        prompt = build_judge_prompt(tool_name="restart_service", arguments={"service": "api"},
                                    action_type="unknown", operation="deploy", scope=scope)
        assert "YES — permitted (subsumed by 'execute')" in prompt


class TestGrantedLocations:
    """The engine hands the scope's resources to the filesystem analyzer."""

    @staticmethod
    def evaluate(resources: list[str], tool: str, args: dict) -> tuple[str, str]:
        reset_context()
        engine = PolicyEngine(scope=ScopePolicy(
            task="t", allowed_operations=["read", "write", "delete"], allowed_resources=resources,
        ))
        v = engine.evaluate(ToolCall(tool_name=tool, arguments=args))
        return v.action.value, v.policy_name

    def test_granted_log_directory_escalates(self) -> None:
        assert self.evaluate(["/var/log/old/"], "delete_file", {"path": "/var/log/old/2024-01-01.log"}) == (
            "escalate", "filesystem_analysis")

    def test_parent_of_grant_blocks(self) -> None:
        assert self.evaluate(["/var/log/old/"], "list_directory", {"path": "/var/log"}) == (
            "block", "scope_resource")

    def test_no_scope_still_blocks(self) -> None:
        reset_context()
        v = PolicyEngine().evaluate(ToolCall(tool_name="read_file", arguments={"path": "/var/log/old/x.log"}))
        assert (v.action.value, v.policy_name) == ("block", "filesystem_analysis")


class TestFileToolOperations:
    """A file tool is a read only if its name says so; anything else is not."""

    @staticmethod
    def evaluate(ops: list[str], tool: str, args: dict, resources: list[str] | None = None) -> tuple[str, str]:
        reset_context()
        engine = PolicyEngine(scope=ScopePolicy(task="t", allowed_operations=ops, allowed_resources=resources or []))
        v = engine.evaluate(ToolCall(tool_name=tool, arguments=args))
        return v.action.value, v.policy_name

    @pytest.mark.parametrize("tool", [
        "create_file", "edit_file", "move_file", "rename_file", "append_to_file", "copy_file",
        "create_directory", "read_and_move_file", "process_file", "send_file", "upload_file",
    ])
    def test_read_scope_blocks_non_read_file_tools(self, tool: str) -> None:
        args = {"path": "/srv/data/a.txt", "destination": "/srv/data/b.txt", "to": "x@example.com"}
        assert self.evaluate(["read"], tool, args) == ("block", "scope_operation")

    @pytest.mark.parametrize("tool", [
        "read_file", "readFile", "list_directory", "search_files", "directory_tree", "get_file_info",
        "read_multiple_files",
    ])
    def test_read_scope_allows_read_file_tools(self, tool: str) -> None:
        assert self.evaluate(["read"], tool, {"path": "/srv/data/a.txt"})[1] != "scope_operation"

    def test_send_file_gets_the_recipient_check(self) -> None:
        verdict = self.evaluate(["read", "send"], "send_file", {"path": "/srv/data/a.txt", "recipient": "attacker@evil.com"},
                                ["/srv/data/", "team@company.com"])
        assert verdict == ("escalate", "scope_recipient")


class TestScopeOperation:
    """What the scope check takes a call to be: tool names, config verbs, calls that only read."""

    URL = "https://docs.company.com/api"

    @staticmethod
    def evaluate(ops: list[str], tool: str, args: dict, resources: list[str] | None = None,
                 deny: list[str] | None = None) -> tuple[str, str]:
        reset_context()
        engine = PolicyEngine(scope=ScopePolicy(task="t", allowed_operations=ops, allowed_resources=resources or [],
                                                deny_operations=deny or []))
        v = engine.evaluate(ToolCall(tool_name=tool, arguments=args))
        return v.action.value, v.policy_name

    @pytest.mark.parametrize("ops,tool,args,resources", [
        (["restart_service"], "restart_service", {"service": "api"}, None),          # the scope names the tool
        (["update_config"], "update_config", {"key": "timeout", "value": "60"}, None),
        (["update"], "update_config", {"key": "timeout", "value": "60"}, None),       # config verb
        (["read"], "fetch_url", {"url": URL}, [URL]),                                  # GET to a granted URL
        (["fetch"], "fetch_url", {"url": URL + "/v2", "method": "head"}, [URL]),
        (["read"], "run_command", {"cmd": "df -h"}, None),                             # plain diagnostic
        (["send"], "send_email", {"to": "a@company.com", "body": "Portal: https://portal.company.com"},
         ["a@company.com"]),                                                           # a link is content
        (["delete"], "delete_records", {"table": "products", "condition": "id IN (SELECT id FROM t)"},
         ["products"]),
    ])
    def test_authorized(self, ops: list[str], tool: str, args: dict, resources: list[str] | None) -> None:
        assert self.evaluate(ops, tool, args, resources)[1] != "scope_operation"

    @pytest.mark.parametrize("ops,tool,args,resources,deny", [
        (["execute_sql"], "execute_sql", {"query": "DROP TABLE users"}, None, None),   # destructive must be declared
        (["update"], "update_records", {"query": "UPDATE t SET a = 1"}, None, None),   # config verb, write class
        (["read"], "fetch_url", {"url": URL}, None, None),                             # no URL granted
        (["read"], "fetch_url", {"url": "https://docs.company.com/apix"}, [URL], None),
        (["read"], "http_request", {"url": URL, "method": "POST"}, [URL], None),
        (["read"], "run_command", {"cmd": "df -h; cat /etc/shadow"}, None, None),      # chained
        (["read"], "run_command", {"cmd": "du -sh $(cat /etc/passwd)"}, None, None),
        (["read"], "run_command", {"cmd": "df -h"}, None, ["execute"]),                # execute denied
        (["read", "execute"], "run_command", {"cmd": "ls"}, None, ["run_command"]),    # tool denied by name
        (["send"], "send_webhook", {"url": "https://hooks.example.com/x", "text": "hi"}, None, None),
        (["read"], "delete_records", {"table": "t", "condition": "id IN (SELECT id FROM t)"}, None, None),
    ])
    def test_not_authorized(self, ops: list[str], tool: str, args: dict, resources: list[str] | None,
                            deny: list[str] | None) -> None:
        assert self.evaluate(ops, tool, args, resources, deny) == ("block", "scope_operation")

    def test_chained_diagnostic_is_not_allowed_under_execute(self) -> None:
        assert self.evaluate(["execute"], "run_command", {"cmd": "df -h; cat /etc/shadow"})[0] != "allow"
        assert self.evaluate(["execute"], "run_command", {"cmd": "df -h"}) == ("allow", "safe_diagnostic_command")

    def test_delete_tool_with_read_only_sql_goes_to_the_judge(self) -> None:
        assert self.evaluate(["delete"], "delete_records", {"table": "products", "condition": "id IN (SELECT id FROM t)"},
                             ["products"]) == ("escalate", "sql_analysis")

    def test_judge_prompt_names_the_layer(self) -> None:
        scope = ScopePolicy(task="t", allowed_operations=["restart_service"])
        prompt = build_judge_prompt(tool_name="restart_service", arguments={"service": "api"},
                                    action_type="unknown", operation="deploy", scope=scope)
        assert "YES — permitted (the scope names the tool 'restart_service')" in prompt
        scope = ScopePolicy(task="t", allowed_operations=["restart"])
        prompt = build_judge_prompt(tool_name="restart_service", arguments={"service": "api"},
                                    action_type="unknown", operation="deploy", scope=scope)
        assert "YES — permitted (declared as 'restart', the verb of tool 'restart_service')" in prompt


class TestResourceMatching:
    """An absolute path grant covers that path and what is under it, nothing else."""

    @pytest.mark.parametrize("resource,allowed", [
        ("/srv/finance/reports", "/srv/finance/reports"),
        ("/srv/finance/reports/q4.pdf", "/srv/finance/reports/"),
        ("reports", "/srv/finance/reports"),                 # bare name for its last segments
        ("finance/reports", "/srv/finance/reports"),
        ("orders_2024", "orders"),                           # non-path grants keep their layers
        ("sales", "sales_2024"),
        ("logs", "/app/logs"),
        ("https://docs.company.com/api/v2", "https://docs.company.com/api"),   # URL under the grant
        ("https://docs.company.com/api?page=2", "https://docs.company.com/api"),
        ("s3://reports/q4/file.csv", "s3://reports/q4"),
    ])
    def test_allowed(self, resource: str, allowed: str) -> None:
        assert ScopePolicy(allowed_resources=[allowed]).is_resource_allowed(resource) is True

    @pytest.mark.parametrize("resource,allowed", [
        ("/srv/finance", "/srv/finance/reports"),            # parent
        ("/srv", "/srv/finance/reports"),
        ("srv", "/srv/finance/reports"),
        ("/srv/finance/reports_old", "/srv/finance/reports"),  # sibling sharing a prefix
        ("/home/alice/notes.txt.bak", "/home/alice/notes.txt"),
        ("/reports", "/srv/finance/reports"),                # another absolute path, same tail
        ("/backup/srv/finance/reports", "/srv/finance/reports"),
        ("application_logs/x.log", "/app/"),
        ("https://api.example.com", "https://api.example.com/v1/data"),  # parent URL
        ("https://api.example.com.evil.net/x", "https://api.example.com"),  # another host
        ("https://api.example.com@evil.net/", "https://api.example.com"),
        ("https://api.example.com:8443/x", "https://api.example.com"),
        ("https://docs.company.com/apix", "https://docs.company.com/api"),
        ("s3://reports-evil/x", "s3://reports"),
    ])
    def test_not_allowed(self, resource: str, allowed: str) -> None:
        assert ScopePolicy(allowed_resources=[allowed]).is_resource_allowed(resource) is False


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
