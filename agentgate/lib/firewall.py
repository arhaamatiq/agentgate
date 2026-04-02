"""AgentGate firewall — the public API surface.

    import agentgate
    agentgate.protect_all()              # one-line setup, patches all detected frameworks
    agentgate.protect_all(config="agentgate.yaml")  # with config-file scopes

    with agentgate.scope(task="...", allowed_operations=[...]):
        run_agent()
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

import yaml

from agentgate.lib.context import get_context
from agentgate.lib.engine import PolicyEngine
from agentgate.lib.engine import register_tools as _engine_register_tools
from agentgate.lib.models import ScopePolicy, ToolCall, Verdict, VerdictType

logger = logging.getLogger("agentgate")

_engine: PolicyEngine | None = None
_patched_frameworks: list[str] = []


class FirewallBlockedError(Exception):
    """Raised when the firewall blocks an agent's tool call.

    Attributes:
        verdict: The Verdict that triggered the block.
        tool_call: The intercepted ToolCall.
    """

    def __init__(self, verdict: Verdict, tool_call: ToolCall | None = None) -> None:
        self.verdict = verdict
        self.tool_call = tool_call
        msg = (
            f"[AgentGate BLOCKED] {verdict.policy_name}: {verdict.reasoning} "
            f"(severity={verdict.severity}, tier={verdict.tier_used})"
        )
        super().__init__(msg)


def get_engine() -> PolicyEngine:
    """Return the global PolicyEngine, initializing if needed."""
    global _engine
    if _engine is None:
        _engine = _create_engine()
    return _engine


def protect_all(
    *,
    config: str | Path | None = None,
    openai_api_key: str | None = None,
    tier2_model: str = "gpt-4o-mini",
    rate_limit: int = 100,
    log_to_supabase: bool = True,
) -> list[str]:
    """One-line setup: auto-detect installed frameworks and patch their tool dispatch.

    Args:
        config: Path to agentgate.yaml config file for scope profiles.
        openai_api_key: API key for Tier 2 LLM-as-judge. Falls back to OPENAI_API_KEY env var.
        tier2_model: Model to use for Tier 2 evaluation.
        rate_limit: Max tool calls per agent per minute.
        log_to_supabase: Whether to enable async audit logging.

    Returns:
        List of framework names that were successfully patched.
    """
    global _engine, _patched_frameworks

    config_data = _load_config(config) if config else {}

    openai_client = _create_tier2_client(openai_api_key)

    _engine = PolicyEngine(
        openai_client=openai_client,
        tier2_model=tier2_model,
        rate_limit=rate_limit,
    )

    if config_data:
        _apply_config(_engine, config_data)

    if log_to_supabase:
        _init_audit_logger()

    _patched_frameworks = _auto_patch()

    _setup_rich_logging()

    if _patched_frameworks:
        logger.info("AgentGate active — patched: %s", ", ".join(_patched_frameworks))
    else:
        logger.info("AgentGate active — no frameworks detected, use @agentgate.guard decorator")

    return _patched_frameworks


@contextmanager
def scope(
    task: str = "",
    allowed_resources: list[str] | None = None,
    allowed_operations: list[str] | None = None,
    deny_operations: list[str] | None = None,
    max_rate: int | None = None,
    agent_id: str = "",
    task_id: str = "",
    user_id: str = "",
) -> Generator[PolicyEngine, None, None]:
    """Context manager to set a scope policy for a block of agent execution.

    Usage::

        with agentgate.scope(
            task="Generate monthly sales report",
            allowed_resources=["sales_data", "reports"],
            allowed_operations=["read", "aggregate", "write"],
        ):
            run_agent(task)
    """
    engine = get_engine()
    previous_scope = engine.scope

    policy = ScopePolicy(
        task=task,
        allowed_resources=allowed_resources or [],
        allowed_operations=allowed_operations or [],
        deny_operations=deny_operations or [],
        max_rate=max_rate,
    )
    engine.set_scope(policy)

    ctx = get_context()
    if agent_id:
        ctx.agent_id = agent_id
    if task_id:
        ctx.task_id = task_id
    if user_id:
        ctx.user_id = user_id
    if task:
        ctx.task_description = task

    try:
        yield engine
    finally:
        engine.scope = previous_scope


def register_tools(tools: dict[str, dict[str, str]]) -> None:
    """Register tools with declared action types and resource keys.

    This allows AgentGate to correctly classify tool operations without
    relying solely on name-based inference. Registered tools take priority
    over default pattern matching.

    Example::

        agentgate.register_tools({
            "execute_sql": {"action_type": "database", "resource_key": "query"},
            "send_email": {"action_type": "communication", "resource_key": "to"},
            "read_logs": {"action_type": "read", "resource_key": "service"},
            "update_config": {"action_type": "config", "resource_key": "key"},
            "deploy_service": {"action_type": "deploy", "resource_key": "service"},
        })

    Valid action_type values: database, read, write, delete, communication,
    config, deploy, export, execute.
    """
    _engine_register_tools(tools)


def guard(func: Any = None, *, tool_name: str = "") -> Any:
    """Decorator to guard a raw Python function as a tool call.

    Usage::

        @agentgate.guard
        def execute_sql(query: str) -> str:
            ...

        @agentgate.guard(tool_name="custom_name")
        def my_func(x):
            ...
    """
    import asyncio
    import functools

    def decorator(fn: Any) -> Any:
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            engine = get_engine()
            tc = ToolCall(tool_name=name, arguments=kwargs or {"args": list(args)})
            verdict = engine.evaluate(tc)
            _handle_verdict(verdict, tc)
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            engine = get_engine()
            tc = ToolCall(tool_name=name, arguments=kwargs or {"args": list(args)})
            verdict = await engine.evaluate_async(tc)
            _handle_verdict(verdict, tc)
            return await fn(*args, **kwargs)

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator


def _handle_verdict(verdict: Verdict, tool_call: ToolCall) -> None:
    """Process a verdict — log and raise if blocked."""
    from agentgate.lib.logger import log_action_fire_and_forget

    ctx = get_context()
    ctx.record_action(tool_call.tool_name, tool_call.arguments, verdict.action.value)

    log_action_fire_and_forget(tool_call, verdict, ctx)

    if verdict.action == VerdictType.BLOCK:
        raise FirewallBlockedError(verdict, tool_call)


def _create_engine(openai_api_key: str | None = None) -> PolicyEngine:
    """Create a default PolicyEngine."""
    client = _create_tier2_client(openai_api_key)
    return PolicyEngine(openai_client=client)


def _create_tier2_client(api_key: str | None = None) -> Any:
    """Create a SEPARATE OpenAI client for Tier 2 LLM-as-judge.

    This is intentionally a different client instance from whatever the agent uses.
    """
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        logger.warning(
            "No OpenAI API key found — Tier 2 (LLM-as-judge) disabled. "
            "Set OPENAI_API_KEY or pass openai_api_key to protect_all()."
        )
        return None

    try:
        from openai import AsyncOpenAI
        return AsyncOpenAI(api_key=key)
    except ImportError:
        logger.warning("OpenAI SDK not installed — Tier 2 disabled.")
        return None


def _auto_patch() -> list[str]:
    """Auto-detect installed frameworks and apply interceptor patches."""
    patched: list[str] = []

    try:
        from agentgate.lib.interceptors.langchain import patch_langchain
        if patch_langchain():
            patched.append("langchain")
    except Exception as e:
        logger.debug("LangChain patch skipped: %s", e)

    try:
        from agentgate.lib.interceptors.openai import patch_openai
        if patch_openai():
            patched.append("openai")
    except Exception as e:
        logger.debug("OpenAI patch skipped: %s", e)

    return patched


def _load_config(config_path: str | Path) -> dict[str, Any]:
    """Load an agentgate.yaml configuration file."""
    path = Path(config_path)
    if not path.exists():
        logger.warning("Config file not found: %s", path)
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _apply_config(engine: PolicyEngine, config: dict[str, Any]) -> None:
    """Apply configuration from agentgate.yaml to the engine."""
    agents = config.get("agents", {})
    if not agents:
        return

    first_agent = next(iter(agents.values()), {})
    if first_agent:
        engine.set_scope(ScopePolicy(
            task=first_agent.get("task", ""),
            allowed_operations=first_agent.get("allowed_operations", []),
            allowed_resources=first_agent.get("allowed_resources", []),
            deny_operations=first_agent.get("deny_operations", []),
            max_rate=first_agent.get("max_rate"),
        ))


def _init_audit_logger() -> None:
    """Initialize the async audit logger if Supabase credentials are available."""
    try:
        from agentgate.lib.logger import AuditLogger
        AuditLogger.initialize()
    except Exception as e:
        logger.debug("Audit logger initialization skipped: %s", e)


def _setup_rich_logging() -> None:
    """Configure Rich-based console logging for AgentGate."""
    try:
        from rich.logging import RichHandler
        handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_path=False,
        )
        ag_logger = logging.getLogger("agentgate")
        if not ag_logger.handlers:
            ag_logger.addHandler(handler)
            ag_logger.setLevel(logging.INFO)
    except ImportError:
        logging.basicConfig(level=logging.INFO)
