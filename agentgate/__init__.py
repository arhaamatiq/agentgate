"""AgentGate — Action-level firewall for AI agents."""

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
