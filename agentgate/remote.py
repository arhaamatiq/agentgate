"""Gateway-backed engine: evaluate tool calls on a central AgentGate gateway.

    agentgate.protect_all(gateway_url="http://agentgate:8080")

Every interceptor (OpenAI, LangChain, @guard) then sends its checks to the Go
gateway instead of evaluating in-process, so one policy, one LLM judge, one
trajectory store and one tamper-evident audit log cover every agent.

Fail-closed: if the gateway cannot be reached, times out, or answers with
anything other than an explicit "allow", the call is BLOCKED.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agentgate.context import get_context
from agentgate.models import ScopePolicy, Severity, ToolCall, Verdict, VerdictType

logger = logging.getLogger("agentgate.remote")


class RemotePolicyEngine:
    """Drop-in replacement for PolicyEngine that asks the gateway."""

    def __init__(self, gateway_url: str, *, timeout: float = 20.0, api_key: str | None = None) -> None:
        import httpx

        self.scope: ScopePolicy | None = None
        self._url = gateway_url.rstrip("/") + "/v1/check"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._sync = httpx.Client(timeout=timeout, headers=headers)
        self._async = httpx.AsyncClient(timeout=timeout, headers=headers)

    def set_scope(self, scope: ScopePolicy) -> None:
        self.scope = scope

    def clear_scope(self) -> None:
        self.scope = None

    def _body(self, tool_call: ToolCall) -> dict[str, Any]:
        ctx = get_context()
        body: dict[str, Any] = {
            "agent_id": ctx.agent_id,
            "session_id": ctx.task_id or ctx.agent_id,
            "user_id": ctx.user_id,
            "task": ctx.task_description,
            "tool_name": tool_call.tool_name,
            "arguments": tool_call.arguments,
        }
        if self.scope is not None:
            body["scope"] = {
                "task": self.scope.task,
                "allowed_operations": self.scope.allowed_operations,
                "allowed_resources": self.scope.allowed_resources,
                "deny_operations": self.scope.deny_operations,
                "max_rate": self.scope.max_rate or 0,
            }
        return body

    @staticmethod
    def _verdict(status: int, payload: Any) -> Verdict:
        if status != 200 or not isinstance(payload, dict) or payload.get("verdict") not in ("allow", "block"):
            return _unavailable(f"unexpected gateway response (HTTP {status})")
        allow = payload["verdict"] == "allow"
        tier = payload.get("tier", 1)
        return Verdict(
            action=VerdictType.ALLOW if allow else VerdictType.BLOCK,
            tier_used=tier if tier in (1, 2) else 1,
            policy_name=str(payload.get("policy", "")),
            severity=_severity(payload.get("severity")),
            reasoning=str(payload.get("reasoning", "")),
        )

    def evaluate(self, tool_call: ToolCall) -> Verdict:
        return self.evaluate_full(tool_call)

    def evaluate_full(self, tool_call: ToolCall, timeout: float | None = None) -> Verdict:
        try:
            r = self._sync.post(self._url, json=self._body(tool_call))
            return self._verdict(r.status_code, _json(r.text))
        except Exception as e:
            return _unavailable(f"{type(e).__name__}: {e}")

    async def evaluate_async(self, tool_call: ToolCall) -> Verdict:
        try:
            r = await self._async.post(self._url, json=self._body(tool_call))
            return self._verdict(r.status_code, _json(r.text))
        except Exception as e:
            return _unavailable(f"{type(e).__name__}: {e}")


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _severity(s: Any) -> Severity:
    try:
        return Severity(s)
    except ValueError:
        return Severity.HIGH


def _unavailable(reason: str) -> Verdict:
    logger.error("AgentGate gateway unavailable: %s", reason)
    return Verdict(
        action=VerdictType.BLOCK,
        tier_used=1,
        policy_name="gateway_unavailable",
        severity=Severity.HIGH,
        reasoning=f"AgentGate gateway unavailable ({reason}) — blocking by default (fail-closed)",
    )
