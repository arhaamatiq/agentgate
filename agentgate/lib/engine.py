"""Two-tier policy evaluation engine.

Tier 1: Fast synchronous static analysis (< 2ms, no API calls, handles ~80% of cases).
Tier 2: Semantic LLM-as-judge for ambiguous cases (100-400ms, gpt-4o-mini).

The Tier 2 LLM is always a separate client instance from the agent's LLM —
different system prompt, reviewer framing, never the same call.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from typing import Any

from agentgate.lib.analyzers.filesystem import FilesystemAnalyzer
from agentgate.lib.analyzers.http import HTTPAnalyzer
from agentgate.lib.analyzers.sql import SQLAnalyzer
from agentgate.lib.context import AgentContext, get_context
from agentgate.lib.models import (
    ActionType,
    ScopePolicy,
    Severity,
    Tier2Response,
    ToolCall,
    Verdict,
    VerdictType,
)

logger = logging.getLogger("agentgate.engine")


def _classify_action(tool_call: ToolCall) -> ActionType:
    """Infer the action type from tool name and arguments.

    Priority: exact name keywords first, then argument content analysis.
    Shell keywords are checked last because they're common substrings.
    """
    name_lower = tool_call.tool_name.lower()
    args_str = json.dumps(tool_call.arguments).lower()

    if any(k in name_lower for k in ("sql", "query", "database", "db")):
        return ActionType.SQL
    if any(k in name_lower for k in ("file", "read_file", "write_file", "path", "fs", "directory")):
        return ActionType.FILESYSTEM
    if any(k in name_lower for k in ("http", "request", "fetch", "curl", "api_call", "url")):
        return ActionType.HTTP
    if any(k in name_lower for k in ("shell", "exec", "command", "bash", "terminal")):
        return ActionType.SHELL

    if any(k in args_str for k in ("select ", "insert ", "update ", "delete ", "drop ")):
        return ActionType.SQL
    if any(k in args_str for k in ("http://", "https://", "ftp://")):
        return ActionType.HTTP

    if any(k in name_lower for k in ("run",)):
        return ActionType.SHELL

    return ActionType.UNKNOWN


def _map_operation(action_type: ActionType, tool_call: ToolCall) -> str:
    """Map an action type to a canonical operation string for scope checking."""
    name_lower = tool_call.tool_name.lower()
    args_str = json.dumps(tool_call.arguments).lower()

    if action_type == ActionType.SQL:
        for op in ("drop", "truncate", "delete", "alter"):
            if op in args_str:
                return "destructive"
        for op in ("insert", "update", "create", "merge"):
            if op in args_str:
                return "write"
        return "read"

    if action_type == ActionType.FILESYSTEM:
        if any(k in name_lower for k in ("write", "save", "create", "delete", "remove")):
            return "write"
        return "read"

    if action_type == ActionType.HTTP:
        return "http"

    if action_type == ActionType.SHELL:
        return "execute"

    return "unknown"


class RateLimiter:
    """Sliding-window rate limiter per agent_id."""

    def __init__(self, max_calls: int = 100, window_seconds: float = 60.0) -> None:
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, agent_id: str) -> bool:
        """Return True if the agent is within rate limits."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        window = self._windows[agent_id]
        self._windows[agent_id] = [t for t in window if t > cutoff]
        self._windows[agent_id].append(now)
        return len(self._windows[agent_id]) <= self.max_calls


_TIER2_SYSTEM_PROMPT = """You are a security reviewer for an AI agent firewall called AgentGate.
Your role is to evaluate whether a tool call made by an AI agent is safe and consistent with its assigned task.

You are NOT the agent. You are an independent reviewer. Be conservative — when in doubt, block.

Evaluate the action and respond with valid JSON matching this schema:
{
  "consistent": boolean,  // Is this action semantically consistent with the stated task?
  "confidence": float,    // 0.0-1.0, how confident you are in your assessment
  "reversible": boolean,  // Is this action easily reversible?
  "reasoning": string     // Brief explanation of your assessment
}

Consider:
1. Is this action semantically consistent with the stated task?
2. Is the blast radius (scope of potential damage) proportionate to the task?
3. Is this action reversible?"""


class PolicyEngine:
    """Two-tier evaluation engine for tool call policy enforcement.

    Tier 1 runs synchronously with zero API calls.
    Tier 2 is async, using a separate OpenAI client instance as LLM-as-judge.
    """

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        openai_client: Any | None = None,
        tier2_model: str = "gpt-4o-mini",
        rate_limit: int = 100,
        rate_window: float = 60.0,
    ) -> None:
        self.scope = scope
        self._openai_client = openai_client
        self._tier2_model = tier2_model
        self._sql_analyzer = SQLAnalyzer()
        self._fs_analyzer = FilesystemAnalyzer()
        self._http_analyzer = HTTPAnalyzer()
        self._rate_limiter = RateLimiter(max_calls=rate_limit, window_seconds=rate_window)
        self._tier2_available = openai_client is not None

    def set_scope(self, scope: ScopePolicy) -> None:
        """Update the active scope policy."""
        self.scope = scope

    def clear_scope(self) -> None:
        """Remove the active scope policy."""
        self.scope = None

    def evaluate(self, tool_call: ToolCall) -> Verdict:
        """Evaluate a tool call — Tier 1 only (synchronous, fast path).

        Returns a clear verdict or ESCALATE if Tier 2 is needed.
        """
        tool_call.action_type = _classify_action(tool_call)

        ctx = get_context()
        if not self._rate_limiter.check(ctx.agent_id):
            return Verdict(
                action=VerdictType.BLOCK,
                tier_used=1,
                policy_name="rate_limit",
                severity=Severity.HIGH,
                reasoning=f"Rate limit exceeded for agent {ctx.agent_id}",
            )

        if self.scope:
            scope_verdict = self._check_scope(tool_call)
            if scope_verdict is not None:
                return scope_verdict

        static_verdict = self._static_analysis(tool_call)
        return static_verdict

    async def evaluate_async(self, tool_call: ToolCall) -> Verdict:
        """Full two-tier evaluation — Tier 1 then Tier 2 if ambiguous.

        This is the primary entry point for interceptors.
        """
        tier1 = self.evaluate(tool_call)

        if tier1.action != VerdictType.ESCALATE:
            return tier1

        if self._tier2_available:
            return await self._tier2_evaluate(tool_call)

        return Verdict(
            action=VerdictType.BLOCK,
            tier_used=2,
            policy_name="no_tier2_fallback",
            severity=Severity.MEDIUM,
            reasoning="Tier 1 ambiguous and Tier 2 unavailable — blocking by default (never fail open)",
        )

    def _check_scope(self, tool_call: ToolCall) -> Verdict | None:
        """Check the tool call against the active scope policy."""
        assert self.scope is not None

        operation = _map_operation(tool_call.action_type, tool_call)

        op_allowed = self.scope.is_operation_allowed(operation)
        if op_allowed is False:
            return Verdict(
                action=VerdictType.BLOCK,
                tier_used=1,
                policy_name="scope_operation",
                severity=Severity.HIGH,
                reasoning=f"Operation '{operation}' not in allowed operations: {self.scope.allowed_operations}",
            )
        if op_allowed is True:
            pass

        for key in ("resource", "path", "table", "database", "file", "url"):
            if key in tool_call.arguments:
                resource = str(tool_call.arguments[key])
                res_allowed = self.scope.is_resource_allowed(resource)
                if res_allowed is False:
                    return Verdict(
                        action=VerdictType.BLOCK,
                        tier_used=1,
                        policy_name="scope_resource",
                        severity=Severity.HIGH,
                        reasoning=f"Resource '{resource}' not in allowed resources: {self.scope.allowed_resources}",
                    )

        return None

    def _static_analysis(self, tool_call: ToolCall) -> Verdict:
        """Run type-specific static analysis (Tier 1)."""
        if tool_call.action_type == ActionType.SQL:
            return self._analyze_sql(tool_call)
        if tool_call.action_type == ActionType.FILESYSTEM:
            return self._analyze_filesystem(tool_call)
        if tool_call.action_type == ActionType.HTTP:
            return self._analyze_http(tool_call)
        if tool_call.action_type == ActionType.SHELL:
            return Verdict(
                action=VerdictType.ESCALATE,
                tier_used=1,
                policy_name="shell_always_escalate",
                severity=Severity.MEDIUM,
                reasoning="Shell commands always escalated to Tier 2",
            )

        return Verdict(
            action=VerdictType.ESCALATE,
            tier_used=1,
            policy_name="unknown_action",
            severity=Severity.LOW,
            reasoning=f"Unknown action type for tool '{tool_call.tool_name}' — escalating",
        )

    def _analyze_sql(self, tool_call: ToolCall) -> Verdict:
        """Run SQL analyzer on the query argument."""
        query = tool_call.arguments.get("query", "")
        if not query:
            query = tool_call.raw_payload or ""

        result = self._sql_analyzer.analyze(query)
        return Verdict(
            action=result.verdict,
            tier_used=1,
            policy_name="sql_analysis",
            severity=result.severity,
            reasoning=result.reasoning,
        )

    def _analyze_filesystem(self, tool_call: ToolCall) -> Verdict:
        """Run filesystem analyzer on the path argument."""
        path = tool_call.arguments.get("path", "")
        if not path:
            path = tool_call.arguments.get("file", "")
        if not path:
            path = tool_call.arguments.get("filename", "")

        operation = tool_call.arguments.get("operation", "read")
        if any(k in tool_call.tool_name.lower() for k in ("write", "save", "delete", "remove")):
            operation = "write"

        result = self._fs_analyzer.analyze(path, operation)
        return Verdict(
            action=result.verdict,
            tier_used=1,
            policy_name="filesystem_analysis",
            severity=result.severity,
            reasoning=result.reasoning,
        )

    def _analyze_http(self, tool_call: ToolCall) -> Verdict:
        """Run HTTP/SSRF analyzer on the URL argument."""
        url = tool_call.arguments.get("url", "")
        if not url:
            url = tool_call.arguments.get("endpoint", "")

        result = self._http_analyzer.analyze(url)
        return Verdict(
            action=result.verdict,
            tier_used=1,
            policy_name="http_analysis",
            severity=result.severity,
            reasoning=result.reasoning,
        )

    async def _tier2_evaluate(self, tool_call: ToolCall) -> Verdict:
        """Tier 2: LLM-as-judge evaluation for ambiguous cases.

        Uses a SEPARATE OpenAI client instance with a reviewer system prompt.
        Never the same client or framing as the agent's LLM.
        """
        ctx = get_context()

        user_prompt = self._build_tier2_prompt(tool_call, ctx)

        try:
            response = await self._openai_client.chat.completions.create(
                model=self._tier2_model,
                messages=[
                    {"role": "system", "content": _TIER2_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=500,
            )

            content = response.choices[0].message.content
            tier2 = Tier2Response.model_validate_json(content)

            should_block = not tier2.consistent or tier2.confidence < 0.7

            return Verdict(
                action=VerdictType.BLOCK if should_block else VerdictType.ALLOW,
                tier_used=2,
                policy_name="llm_judge",
                severity=Severity.HIGH if should_block else Severity.LOW,
                reasoning=tier2.reasoning,
                confidence=tier2.confidence,
                reversible=tier2.reversible,
            )

        except Exception as e:
            logger.error("Tier 2 evaluation failed: %s", e)
            return Verdict(
                action=VerdictType.BLOCK,
                tier_used=2,
                policy_name="tier2_error",
                severity=Severity.MEDIUM,
                reasoning=f"Tier 2 evaluation failed ({type(e).__name__}) — blocking by default",
            )

    def _build_tier2_prompt(self, tool_call: ToolCall, ctx: AgentContext) -> str:
        """Build the user prompt for Tier 2 evaluation."""
        recent_actions = list(ctx.action_history)[-10:]

        return json.dumps({
            "task_context": {
                "task_description": ctx.task_description or self.scope.task if self.scope else "Not specified",
                "agent_id": ctx.agent_id,
                "user_id": ctx.user_id,
            },
            "recent_action_history": recent_actions,
            "current_tool_call": {
                "tool_name": tool_call.tool_name,
                "arguments": tool_call.arguments,
                "action_type": tool_call.action_type.value,
            },
            "scope_policy": {
                "allowed_operations": self.scope.allowed_operations if self.scope else [],
                "allowed_resources": self.scope.allowed_resources if self.scope else [],
            },
        }, indent=2)
