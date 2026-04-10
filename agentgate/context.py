"""Thread-safe, async-safe context propagation using Python contextvars.

Set once at agent startup, available everywhere without explicit passing.
Works for both sync and async execution paths.
"""

from __future__ import annotations

import uuid
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentContext:
    """Carries identity and history for a single agent execution.

    Attributes:
        agent_id: Unique identifier for the agent instance.
        task_id: Identifier for the current task/run.
        user_id: Identifier for the human who initiated the session.
        action_history: Rolling window of the last N tool calls.
        task_description: Natural-language description of the agent's current task.
        metadata: Arbitrary extra context.
    """

    agent_id: str = ""
    task_id: str = ""
    user_id: str = ""
    action_history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=50))
    task_description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def record_action(self, tool_name: str, arguments: dict[str, Any], verdict: str) -> None:
        """Append a tool call to the rolling action history."""
        self.action_history.append({
            "tool_name": tool_name,
            "arguments": arguments,
            "verdict": verdict,
        })


_agent_context_var: ContextVar[AgentContext | None] = ContextVar(
    "agentgate_context", default=None
)


def get_context() -> AgentContext:
    """Return the current AgentContext, creating a default if none is set."""
    ctx = _agent_context_var.get()
    if ctx is None:
        ctx = AgentContext(agent_id=f"auto-{uuid.uuid4().hex[:8]}")
        _agent_context_var.set(ctx)
    return ctx


def set_context(ctx: AgentContext) -> None:
    """Explicitly set the AgentContext for the current execution scope."""
    _agent_context_var.set(ctx)


def reset_context() -> None:
    """Clear the current AgentContext."""
    _agent_context_var.set(None)


class agent_context:
    """Context manager to set AgentContext for a block of code.

    Usage::

        with agent_context(agent_id="report-bot", task_id="run-42"):
            run_agent()
    """

    def __init__(
        self,
        agent_id: str = "",
        task_id: str = "",
        user_id: str = "",
        task_description: str = "",
        **metadata: Any,
    ) -> None:
        self._ctx = AgentContext(
            agent_id=agent_id or f"auto-{uuid.uuid4().hex[:8]}",
            task_id=task_id or f"task-{uuid.uuid4().hex[:8]}",
            user_id=user_id,
            task_description=task_description,
            metadata=metadata,
        )
        self._token: Any = None

    def __enter__(self) -> AgentContext:
        self._token = _agent_context_var.set(self._ctx)
        return self._ctx

    def __exit__(self, *exc: Any) -> None:
        _agent_context_var.reset(self._token)

    async def __aenter__(self) -> AgentContext:
        return self.__enter__()

    async def __aexit__(self, *exc: Any) -> None:
        self.__exit__(*exc)
