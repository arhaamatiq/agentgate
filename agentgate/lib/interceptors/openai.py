"""OpenAI SDK interceptor — patches tool call dispatch in chat completions.

The OpenAI Python SDK returns tool_calls in ChatCompletion responses. Agents then
dispatch these calls to actual functions. We intercept at the point where the SDK's
response is processed, wrapping the chat.completions.create method to inspect
tool_calls BEFORE the agent acts on them.

This means the agent gets a FirewallBlockedError (or a modified response) before
any side-effecting tool function is executed.
"""

from __future__ import annotations

import functools
import json
import logging
from typing import Any

logger = logging.getLogger("agentgate.interceptors.openai")

_original_create: Any = None
_original_async_create: Any = None
_patched = False


def patch_openai() -> bool:
    """Patch the OpenAI SDK to evaluate tool calls through AgentGate.

    Wraps both sync and async chat.completions.create to intercept tool_calls
    in the response before the agent dispatches them.

    Returns True if the patch was applied, False if OpenAI SDK is not installed.
    """
    global _original_create, _original_async_create, _patched

    if _patched:
        return True

    try:
        from openai.resources.chat.completions import Completions, AsyncCompletions
    except ImportError:
        logger.debug("OpenAI SDK not installed — skipping OpenAI patch")
        return False

    _original_create = Completions.create
    _original_async_create = AsyncCompletions.create

    @functools.wraps(_original_create)
    def guarded_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        response = _original_create(self, *args, **kwargs)
        _evaluate_tool_calls_sync(response)
        return response

    @functools.wraps(_original_async_create)
    async def guarded_async_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        response = await _original_async_create(self, *args, **kwargs)
        await _evaluate_tool_calls_async(response)
        return response

    Completions.create = guarded_create  # type: ignore[assignment]
    AsyncCompletions.create = guarded_async_create  # type: ignore[assignment]
    _patched = True

    logger.info("OpenAI SDK patched — tool calls in responses routed through AgentGate")
    return True


def unpatch_openai() -> None:
    """Restore original OpenAI SDK methods (for testing)."""
    global _original_create, _original_async_create, _patched

    if not _patched:
        return

    try:
        from openai.resources.chat.completions import Completions, AsyncCompletions
        if _original_create is not None:
            Completions.create = _original_create
        if _original_async_create is not None:
            AsyncCompletions.create = _original_async_create
        _patched = False
    except ImportError:
        pass


def _evaluate_tool_calls_sync(response: Any) -> None:
    """Evaluate tool calls in a sync ChatCompletion response."""
    tool_calls = _extract_tool_calls(response)
    if not tool_calls:
        return

    from agentgate.lib.firewall import get_engine, _handle_verdict
    from agentgate.lib.models import ToolCall

    engine = get_engine()

    for tc_data in tool_calls:
        tc = ToolCall(
            tool_name=tc_data["name"],
            arguments=tc_data["arguments"],
        )
        verdict = engine.evaluate(tc)
        _handle_verdict(verdict, tc)


async def _evaluate_tool_calls_async(response: Any) -> None:
    """Evaluate tool calls in an async ChatCompletion response."""
    tool_calls = _extract_tool_calls(response)
    if not tool_calls:
        return

    from agentgate.lib.firewall import get_engine, _handle_verdict
    from agentgate.lib.models import ToolCall

    engine = get_engine()

    for tc_data in tool_calls:
        tc = ToolCall(
            tool_name=tc_data["name"],
            arguments=tc_data["arguments"],
        )
        verdict = await engine.evaluate_async(tc)
        _handle_verdict(verdict, tc)


def _extract_tool_calls(response: Any) -> list[dict[str, Any]]:
    """Extract tool call data from an OpenAI ChatCompletion response."""
    results: list[dict[str, Any]] = []

    try:
        choices = getattr(response, "choices", [])
        for choice in choices:
            message = getattr(choice, "message", None)
            if message is None:
                continue
            tool_calls = getattr(message, "tool_calls", None)
            if not tool_calls:
                continue
            for tc in tool_calls:
                func = getattr(tc, "function", None)
                if func is None:
                    continue
                name = getattr(func, "name", "unknown")
                args_str = getattr(func, "arguments", "{}")
                try:
                    arguments = json.loads(args_str)
                except (json.JSONDecodeError, TypeError):
                    arguments = {"raw": args_str}
                results.append({"name": name, "arguments": arguments})
    except Exception as e:
        logger.warning("Failed to extract tool calls from response: %s", e)

    return results
