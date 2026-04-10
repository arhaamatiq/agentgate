"""Rich Live two-panel display for the AgentGate demo.

Left panel  — "Agent Activity":  scrolling narrative lines from the agent.
Right panel — "AgentGate Firewall": intercept table with verdict per tool call.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime
from typing import Any

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Pattern for structured agentgate.logger debug messages:
# "action: tool=<name> verdict=<v> tier=<n> <reasoning>"
_ACTION_RE = re.compile(
    r"action:\s+tool=(\S+)\s+verdict=(\S+)\s+tier=(\d+)\s+(.*)",
    re.IGNORECASE | re.DOTALL,
)


class DemoDisplay:
    """Rich Live two-panel display: agent narrative (left) + firewall log (right)."""

    def __init__(self) -> None:
        self._console = Console()
        self._agent_lines: list[tuple[str, str]] = []   # (timestamp, text)
        self._intercept_rows: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._live: Live | None = None

        self._layout = Layout()
        self._layout.split_row(
            Layout(name="agent", ratio=1),
            Layout(name="firewall", ratio=1),
        )
        self._layout["agent"].update(self._build_agent_panel())
        self._layout["firewall"].update(self._build_firewall_panel())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Rich Live context."""
        self._live = Live(
            self._layout,
            console=self._console,
            refresh_per_second=10,
            screen=False,
            vertical_overflow="visible",
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the Rich Live context."""
        if self._live:
            self._live.stop()
            self._live = None

    # ------------------------------------------------------------------
    # Public update methods
    # ------------------------------------------------------------------

    def add_agent_line(self, text: str) -> None:
        """Append a narrative line to the left panel."""
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._agent_lines.append((ts, text))
        self._refresh()

    def add_intercept(
        self,
        tool_name: str,
        verdict: str,
        reason: str,
        tier: int,
        latency_ms: float,
    ) -> None:
        """Append an intercept row to the right panel table."""
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._intercept_rows.append({
                "time": ts,
                "tool": tool_name,
                "verdict": verdict.upper(),
                "reason": reason,
                "tier": tier,
                "latency": f"{latency_ms:.0f}ms",
            })
        self._refresh()

    # ------------------------------------------------------------------
    # Counters (used in summary)
    # ------------------------------------------------------------------

    @property
    def total_count(self) -> int:
        with self._lock:
            return len(self._intercept_rows)

    @property
    def allowed_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._intercept_rows if r["verdict"] == "ALLOW")

    @property
    def blocked_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._intercept_rows if r["verdict"] == "BLOCK")

    # ------------------------------------------------------------------
    # Panel builders
    # ------------------------------------------------------------------

    def _build_agent_panel(self) -> Panel:
        text = Text()
        with self._lock:
            lines = list(self._agent_lines[-20:])
        for ts, line in lines:
            text.append(ts + "  ", style="dim")
            text.append(line + "\n")
        return Panel(
            text,
            title="[bold blue] Agent Activity [/bold blue]",
            border_style="blue",
            padding=(0, 1),
        )

    def _build_firewall_panel(self) -> Panel:
        table = Table(
            show_header=True,
            box=box.SIMPLE_HEAD,
            padding=(0, 1),
            expand=True,
            show_edge=False,
        )
        table.add_column("Time", style="dim", no_wrap=True, width=8)
        table.add_column("Tool", no_wrap=True, width=13)
        table.add_column("Verdict", no_wrap=True, width=7)
        table.add_column("Reason", overflow="fold")
        table.add_column("T", no_wrap=True, width=2)
        table.add_column("ms", no_wrap=True, width=6)

        with self._lock:
            rows = list(self._intercept_rows)

        for row in rows:
            verdict = row["verdict"]
            if verdict == "ALLOW":
                v_text = Text("ALLOW", style="bold green")
                row_style = ""
            else:
                v_text = Text("BLOCK", style="bold red")
                row_style = "red"

            reason = row["reason"]
            if len(reason) > 80:
                reason = reason[:77] + "..."

            table.add_row(
                row["time"],
                row["tool"],
                v_text,
                reason,
                str(row["tier"]),
                row["latency"],
                style=row_style,
            )

        return Panel(
            table,
            title="[bold red] AgentGate Firewall [/bold red]",
            border_style="red",
            padding=(0, 1),
        )

    def _refresh(self) -> None:
        if self._live is None:
            return
        self._layout["agent"].update(self._build_agent_panel())
        self._layout["firewall"].update(self._build_firewall_panel())


class AgentGateLogHandler(logging.Handler):
    """Logging handler that bridges agentgate logger output to the demo display.

    Attaches to ``logging.getLogger("agentgate")`` in run_demo.py.

    Parses structured agentgate debug messages in the format::

        action: tool=<name> verdict=<allow|block> tier=<n> <reasoning>

    and routes intercept data to DemoDisplay. Falls back gracefully if parsing
    fails — suppressing console noise keeps the Rich Live display clean.

    Note: In the demo scenario, ``add_intercept()`` is also called directly from
    the scenario wrapper for accurate wall-clock timing. The handler captures any
    additional log-driven intercept events (e.g. from async paths) and deduplicates
    via ``set_pending()``.
    """

    def __init__(self, display: DemoDisplay) -> None:
        super().__init__(level=logging.DEBUG)
        self._display = display
        self._pending_start: dict[str, float] = {}

    def set_pending(self, tool_name: str) -> None:
        """Record the start time for an imminent tool invocation."""
        self._pending_start[tool_name] = time.perf_counter()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            m = _ACTION_RE.match(msg)
            if m:
                tool_name, verdict_str, tier_str, reason = m.groups()
                tier = int(tier_str)
                verdict = verdict_str.upper()
                start = self._pending_start.pop(tool_name, None)
                latency_ms = (time.perf_counter() - start) * 1000 if start else 0.0
                self._display.add_intercept(
                    tool_name, verdict, reason.strip(), tier, latency_ms
                )
        except Exception:
            pass  # never let the logging handler crash the demo
