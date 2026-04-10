"""LangChain/LangGraph interceptor — patches BaseTool._run and _arun.

When an agent invokes any LangChain tool, the call flows through BaseTool._run
(sync) or BaseTool._arun (async). We monkey-patch these methods to insert
AgentGate evaluation BEFORE the actual tool execution.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

logger = logging.getLogger("agentgate.interceptors.langchain")

_original_run: Any = None
_original_arun: Any = None
_patched = False


def patch_langchain() -> bool:
    """Patch LangChain's BaseTool to route all tool calls through AgentGate.

    Returns True if the patch was applied, False if LangChain is not installed.
    """
    global _original_run, _original_arun, _patched

    if _patched:
        return True

    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        logger.debug("langchain-core not installed — skipping LangChain patch")
        return False

    _original_run = BaseTool._run
    _original_arun = BaseTool._arun

    @functools.wraps(_original_run)
    def guarded_run(self: Any, *args: Any, **kwargs: Any) -> Any:
        from agentgate.firewall import get_engine, _handle_verdict
        from agentgate.models import ToolCall

        tool_input = kwargs if kwargs else {"input": args[0] if args else ""}
        tc = ToolCall(tool_name=self.name, arguments=tool_input)

        engine = get_engine()
        verdict = engine.evaluate(tc)
        _handle_verdict(verdict, tc)

        return _original_run(self, *args, **kwargs)

    @functools.wraps(_original_arun)
    async def guarded_arun(self: Any, *args: Any, **kwargs: Any) -> Any:
        from agentgate.firewall import get_engine, _handle_verdict
        from agentgate.models import ToolCall

        tool_input = kwargs if kwargs else {"input": args[0] if args else ""}
        tc = ToolCall(tool_name=self.name, arguments=tool_input)

        engine = get_engine()
        verdict = await engine.evaluate_async(tc)
        _handle_verdict(verdict, tc)

        return await _original_arun(self, *args, **kwargs)

    BaseTool._run = guarded_run  # type: ignore[assignment]
    BaseTool._arun = guarded_arun  # type: ignore[assignment]
    _patched = True

    logger.info("LangChain BaseTool patched — all tool calls routed through AgentGate")
    return True


def unpatch_langchain() -> None:
    """Restore original BaseTool methods (for testing)."""
    global _original_run, _original_arun, _patched

    if not _patched:
        return

    try:
        from langchain_core.tools import BaseTool
        if _original_run is not None:
            BaseTool._run = _original_run
        if _original_arun is not None:
            BaseTool._arun = _original_arun
        _patched = False
    except ImportError:
        pass
