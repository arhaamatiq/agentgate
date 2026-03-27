"""Async, non-blocking audit logger — fire-and-forget to Supabase.

Uses asyncio.create_task() so logging NEVER adds latency to the critical path.
Logs every intercepted action (allowed and blocked) to the actions table,
and violations separately to the violations table.

Schema designed for a future real-time Next.js dashboard via Supabase Realtime.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from agentgate.lib.context import AgentContext, get_context
from agentgate.lib.models import (
    AuditRecord,
    ToolCall,
    Verdict,
    VerdictType,
    ViolationRecord,
)

logger = logging.getLogger("agentgate.logger")


class AuditLogger:
    """Async audit logger that writes to Supabase without blocking.

    All writes are fire-and-forget via asyncio.create_task().
    If Supabase is unavailable, logs degrade gracefully to stderr.
    """

    _instance: AuditLogger | None = None
    _client: Any = None
    _enabled: bool = False

    @classmethod
    def initialize(
        cls,
        supabase_url: str | None = None,
        supabase_key: str | None = None,
    ) -> AuditLogger:
        """Initialize the singleton audit logger.

        Falls back to SUPABASE_URL / SUPABASE_KEY environment variables.
        """
        if cls._instance is not None:
            return cls._instance

        url = supabase_url or os.environ.get("SUPABASE_URL", "")
        key = supabase_key or os.environ.get("SUPABASE_KEY", "")

        instance = cls()

        if url and key:
            try:
                from supabase import create_client
                instance._client = create_client(url, key)
                instance._enabled = True
                logger.info("Audit logger connected to Supabase")
            except Exception as e:
                logger.warning("Supabase client init failed: %s — logging to stderr only", e)
                instance._enabled = False
        else:
            logger.debug(
                "SUPABASE_URL/SUPABASE_KEY not set — audit logging to stderr only"
            )
            instance._enabled = False

        cls._instance = instance
        return instance

    @classmethod
    def get(cls) -> AuditLogger:
        """Get the singleton instance, initializing with defaults if needed."""
        if cls._instance is None:
            return cls.initialize()
        return cls._instance

    async def log_action(self, record: AuditRecord) -> None:
        """Write an audit record to the actions table."""
        if self._enabled and self._client:
            try:
                data = record.model_dump(mode="json")
                self._client.table("actions").insert(data).execute()
            except Exception as e:
                logger.warning("Failed to log action to Supabase: %s", e)

        logger.debug(
            "action: tool=%s verdict=%s tier=%d %s",
            record.tool_name,
            record.verdict.value if hasattr(record.verdict, 'value') else record.verdict,
            record.tier_used,
            record.reasoning,
        )

    async def log_violation(self, violation: ViolationRecord) -> None:
        """Write a violation record to the violations table."""
        if self._enabled and self._client:
            try:
                data = violation.model_dump(mode="json")
                self._client.table("violations").insert(data).execute()
            except Exception as e:
                logger.warning("Failed to log violation to Supabase: %s", e)

        logger.debug(
            "violation: action_id=%s severity=%s",
            violation.action_id,
            violation.severity,
        )

    async def log_full(
        self,
        tool_call: ToolCall,
        verdict: Verdict,
        ctx: AgentContext,
    ) -> None:
        """Log an action and, if blocked, a violation — full pipeline."""
        record = AuditRecord(
            agent_id=ctx.agent_id,
            task_id=ctx.task_id,
            user_id=ctx.user_id,
            tool_name=tool_call.tool_name,
            payload=tool_call.arguments,
            verdict=verdict.action,
            policy_name=verdict.policy_name,
            severity=verdict.severity.value if hasattr(verdict.severity, 'value') else str(verdict.severity),
            tier_used=verdict.tier_used,
            reasoning=verdict.reasoning,
        )
        await self.log_action(record)

        if verdict.action == VerdictType.BLOCK:
            violation = ViolationRecord(
                action_id=record.id,
                severity=record.severity,
                details={
                    "tool_name": tool_call.tool_name,
                    "arguments": tool_call.arguments,
                    "policy_name": verdict.policy_name,
                    "reasoning": verdict.reasoning,
                },
            )
            await self.log_violation(violation)


def log_action_fire_and_forget(
    tool_call: ToolCall,
    verdict: Verdict,
    ctx: AgentContext | None = None,
) -> None:
    """Fire-and-forget audit log — never blocks the critical path.

    Uses asyncio.create_task() if an event loop is running,
    otherwise falls back to synchronous logging.
    """
    if ctx is None:
        ctx = get_context()

    audit_logger = AuditLogger.get()

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(audit_logger.log_full(tool_call, verdict, ctx))
    except RuntimeError:
        import threading
        thread = threading.Thread(
            target=_sync_log_wrapper,
            args=(audit_logger, tool_call, verdict, ctx),
            daemon=True,
        )
        thread.start()


def _sync_log_wrapper(
    audit_logger: AuditLogger,
    tool_call: ToolCall,
    verdict: Verdict,
    ctx: AgentContext,
) -> None:
    """Run the async log_full in a new event loop on a background thread."""
    try:
        asyncio.run(audit_logger.log_full(tool_call, verdict, ctx))
    except Exception as e:
        logger.warning("Background audit log failed: %s", e)
