"""Gateway-backed engine: verdict mapping and fail-closed behavior."""

from __future__ import annotations

import pytest

import agentgate.firewall as fw
from agentgate.firewall import FirewallBlockedError, guard, scope
from agentgate.models import VerdictType
from agentgate.remote import RemotePolicyEngine


@pytest.fixture(autouse=True)
def _reset_engine():
    fw._engine = None
    yield
    fw._engine = None


def test_unreachable_gateway_blocks() -> None:
    fw._engine = RemotePolicyEngine("http://127.0.0.1:9", timeout=0.5)
    ran = []

    @guard
    def read_file(path: str) -> str:
        ran.append(path)
        return "contents"

    with scope(task="read reports", allowed_operations=["read"], allowed_resources=["/reports"]):
        with pytest.raises(FirewallBlockedError) as e:
            read_file("/reports/q4.csv")
    assert ran == []
    assert e.value.verdict.policy_name == "gateway_unavailable"


def test_verdict_mapping_is_strict() -> None:
    v = RemotePolicyEngine._verdict(200, {"verdict": "allow", "tier": 1, "policy": "p", "severity": "low"})
    assert v.action == VerdictType.ALLOW
    for status, payload in [(500, {"verdict": "allow"}), (200, {"verdict": "escalate"}), (200, None), (200, "allow")]:
        assert RemotePolicyEngine._verdict(status, payload).action == VerdictType.BLOCK
