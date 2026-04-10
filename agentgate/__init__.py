"""AgentGate — action-level firewall for AI agents."""
from __future__ import annotations


def _load_dotenv() -> None:
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        return
    path = find_dotenv(usecwd=True)
    if path:
        load_dotenv(path)


_load_dotenv()

from agentgate.firewall import protect_all, scope, guard, register_tools, FirewallBlockedError
from agentgate.context import AgentContext, agent_context
from agentgate.engine import PolicyEngine
from agentgate.models import Verdict, VerdictType

__version__ = "0.1.0"
__all__ = [
    "protect_all",
    "scope",
    "guard",
    "register_tools",
    "FirewallBlockedError",
    "AgentContext",
    "agent_context",
    "PolicyEngine",
    "Verdict",
    "VerdictType",
    "__version__",
]
