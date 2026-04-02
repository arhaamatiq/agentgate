"""AgentGate — Action-level firewall for AI agents."""

from __future__ import annotations


def _load_dotenv() -> None:
    """Load `.env` from the current working directory (walks upward like git)."""
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        return
    path = find_dotenv(usecwd=True)
    if path:
        load_dotenv(path)


_load_dotenv()

from agentgate.lib.firewall import protect_all, scope, FirewallBlockedError
from agentgate.lib.context import AgentContext, agent_context
from agentgate.lib.engine import PolicyEngine, Verdict

__all__ = [
    "protect_all",
    "scope",
    "FirewallBlockedError",
    "AgentContext",
    "agent_context",
    "PolicyEngine",
    "Verdict",
]
