"""Pydantic v2 data models for AgentGate's evaluation pipeline."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class ActionType(str, enum.Enum):
    """Categories of tool actions the firewall can classify."""

    SQL = "sql"
    FILESYSTEM = "filesystem"
    HTTP = "http"
    SHELL = "shell"
    CODE_EXEC = "code_exec"
    UNKNOWN = "unknown"


class Severity(str, enum.Enum):
    """Severity levels for policy violations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictType(str, enum.Enum):
    """Possible outcomes from the evaluation engine."""

    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


class ToolCall(BaseModel):
    """Represents a single tool invocation intercepted by AgentGate."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_payload: str | None = None
    action_type: ActionType = ActionType.UNKNOWN
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScopePolicy(BaseModel):
    """Defines what an agent is allowed to do within a given scope."""

    task: str = ""
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_operations: list[str] = Field(default_factory=list)
    max_rate: int | None = None
    deny_operations: list[str] = Field(default_factory=list)

    # Broad operations subsume narrower ones. If "write" is declared as allowed,
    # then "config", "send", "export" etc. are implicitly permitted.
    _OPERATION_SUBSUMPTION: dict[str, frozenset[str]] = {
        "write": frozenset({"config", "send", "export", "update", "notify", "forward", "broadcast", "post"}),
        "execute": frozenset({"deploy", "restart", "run", "start", "stop", "bounce"}),
        "destructive": frozenset({"delete", "purge", "drop", "truncate", "remove", "flush", "wipe"}),
        "read": frozenset({"list", "get", "describe", "fetch", "check", "show", "monitor", "tail", "inspect"}),
        "send": frozenset({"notify", "forward", "broadcast", "post"}),
        "deploy": frozenset({"restart", "bounce", "rollout", "release"}),
    }

    def is_operation_allowed(self, operation: str) -> bool | None:
        """Check if an operation is allowed by this policy.

        Returns True if explicitly allowed, False if explicitly denied,
        None if the policy has no opinion (no allowed_operations declared).

        Matching layers (first match wins):
          1. Direct string equality.
          2. Underscore-prefix matching: "config" matches "config_tune".
          3. Subsumption: if "write" is allowed, then "config"/"send"/"export" pass.
        """
        if operation in self.deny_operations:
            return False
        if not self.allowed_operations:
            return None
        for allowed_op in self.allowed_operations:
            if operation == allowed_op:
                return True
            if allowed_op.startswith(operation + "_"):
                return True
            if operation.startswith(allowed_op + "_"):
                return True
            subsumes = self._OPERATION_SUBSUMPTION.get(allowed_op, frozenset())
            if operation in subsumes:
                return True
        return False

    def is_resource_allowed(self, resource: str) -> bool | None:
        """Check if a resource is allowed by this policy.

        Returns None if no resource restrictions are declared.

        Matching layers:
          1. Exact match after normalizing leading/trailing slashes.
          2. Forward prefix — resource is under the allowed path.
          3. Reverse prefix at a word boundary (``-``, ``_``, ``/``, ``.``).
          4. Path-suffix — bare name matches the last segments of the allowed
             path (e.g. ``"uploads"`` matches ``"/app/uploads/"``).
        """
        if not self.allowed_resources:
            return None
        resource_norm = resource.lower().strip("/").strip()
        if not resource_norm:
            return None
        resource_parts = resource_norm.split("/")

        for allowed in self.allowed_resources:
            allowed_norm = allowed.lower().strip("/").strip()
            if not allowed_norm:
                continue
            allowed_parts = allowed_norm.split("/")

            if resource_norm == allowed_norm:
                return True

            if resource_norm.startswith(allowed_norm + "/") or resource_norm.startswith(allowed_norm):
                return True

            if allowed_norm.startswith(resource_norm) and len(resource_norm) < len(allowed_norm):
                if allowed_norm[len(resource_norm)] in "-_./":
                    return True

            if len(resource_parts) < len(allowed_parts):
                if resource_parts == allowed_parts[-len(resource_parts):]:
                    return True
            if len(allowed_parts) < len(resource_parts):
                if allowed_parts == resource_parts[-len(allowed_parts):]:
                    return True

        return False


class Verdict(BaseModel):
    """The outcome of evaluating a tool call against policy."""

    action: VerdictType
    tier_used: int = Field(ge=1, le=2)
    policy_name: str = ""
    severity: Severity = Severity.LOW
    reasoning: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reversible: bool = True


class Tier2Response(BaseModel):
    """Structured response from the LLM-as-judge (Tier 2)."""

    consistent: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reversible: bool
    reasoning: str


class AuditRecord(BaseModel):
    """A single audit log entry for Supabase."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str = ""
    task_id: str = ""
    user_id: str = ""
    tool_name: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    verdict: VerdictType = VerdictType.ALLOW
    policy_name: str = ""
    severity: str = "low"
    tier_used: int = 1
    reasoning: str = ""


class ViolationRecord(BaseModel):
    """A policy violation entry for Supabase."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "low"
    details: dict[str, Any] = Field(default_factory=dict)
