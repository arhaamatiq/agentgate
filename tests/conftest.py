"""Shared fixtures. The suite never calls a live LLM."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_live_judge(monkeypatch: pytest.MonkeyPatch) -> None:
    # agentgate/__init__ loads .env; strip judge credentials so Tier 2 is
    # either mocked explicitly or unavailable (which must fail closed).
    for var in ("OPENAI_API_KEY", "AGENTGATE_JUDGE_API_KEY", "AGENTGATE_JUDGE_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
