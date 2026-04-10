"""Simulated agent tools, each guarded by @agentgate.guard.

Bodies are stubs: short sleep + realistic return value.
No real database, filesystem, or network connections are made.
"""

from __future__ import annotations

import time

import agentgate


@agentgate.guard
def execute_sql(query: str) -> str:
    time.sleep(0.05)
    return f"SQL executed: {query[:60]}"


@agentgate.guard
def read_file(path: str) -> str:
    time.sleep(0.03)
    return f"File contents of {path}"


@agentgate.guard
def http_request(url: str, method: str = "GET") -> str:
    time.sleep(0.04)
    return f"{method} {url} → 200 OK"


@agentgate.guard
def write_file(path: str, content: str) -> str:
    time.sleep(0.03)
    return f"Written to {path}"


@agentgate.guard
def send_email(to: str, subject: str, body: str) -> str:
    time.sleep(0.04)
    return f"Email sent to {to}"
