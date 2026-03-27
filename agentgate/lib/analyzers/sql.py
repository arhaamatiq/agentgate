"""SQL static analysis using sqlparse AST.

Two-pass approach:
  1. Fast string match for obviously destructive keywords.
  2. Full AST parse to catch obfuscation (e.g. comments, mixed case, concatenation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

import sqlparse
from sqlparse.sql import Statement
from sqlparse.tokens import Keyword, DML, DDL

from agentgate.lib.models import Severity, VerdictType


@dataclass
class SQLAnalysisResult:
    """Outcome of analyzing a SQL statement."""

    verdict: VerdictType
    severity: Severity
    reasoning: str
    statement_types: list[str]

    @property
    def is_destructive(self) -> bool:
        return self.verdict == VerdictType.BLOCK


_DESTRUCTIVE_KEYWORDS: set[str] = {"DROP", "TRUNCATE", "DELETE", "ALTER", "GRANT", "REVOKE"}
_WRITE_KEYWORDS: set[str] = {"INSERT", "UPDATE", "CREATE", "MERGE", "UPSERT", "REPLACE"}
_SAFE_KEYWORDS: set[str] = {"SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "WITH"}

_FAST_DESTRUCTIVE_RE = re.compile(
    r"\b(DROP|TRUNCATE|DELETE\s+FROM|ALTER\s+TABLE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)

_COMMENT_OBFUSCATION_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


class SQLAnalyzer:
    """Analyzes SQL statements for destructive operations.

    Pass 1: Fast regex scan for obvious destructive patterns.
    Pass 2: Full sqlparse AST walk to catch obfuscated or multi-statement SQL.
    """

    DESTRUCTIVE_KEYWORDS: ClassVar[set[str]] = _DESTRUCTIVE_KEYWORDS
    WRITE_KEYWORDS: ClassVar[set[str]] = _WRITE_KEYWORDS

    def analyze(self, sql: str) -> SQLAnalysisResult:
        """Analyze a SQL string and return a verdict.

        Args:
            sql: Raw SQL statement(s) to evaluate.

        Returns:
            SQLAnalysisResult with verdict, severity, and detected statement types.
        """
        if not sql or not sql.strip():
            return SQLAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="Empty SQL statement",
                statement_types=[],
            )

        fast_result = self._fast_pass(sql)
        if fast_result is not None:
            return fast_result

        return self._ast_pass(sql)

    def _fast_pass(self, sql: str) -> SQLAnalysisResult | None:
        """Pass 1: Fast regex check for obviously destructive SQL."""
        stripped = _COMMENT_OBFUSCATION_RE.sub("", sql)

        match = _FAST_DESTRUCTIVE_RE.search(stripped)
        if match:
            keyword = match.group(1).split()[0].upper()
            return SQLAnalysisResult(
                verdict=VerdictType.BLOCK,
                severity=Severity.CRITICAL if keyword in {"DROP", "TRUNCATE"} else Severity.HIGH,
                reasoning=f"Destructive SQL operation detected: {keyword}",
                statement_types=[keyword],
            )
        return None

    def _ast_pass(self, sql: str) -> SQLAnalysisResult:
        """Pass 2: Full AST analysis with sqlparse for obfuscation resilience."""
        try:
            parsed = sqlparse.parse(sql)
        except Exception:
            return SQLAnalysisResult(
                verdict=VerdictType.ESCALATE,
                severity=Severity.MEDIUM,
                reasoning="SQL could not be parsed — escalating to Tier 2",
                statement_types=["UNPARSEABLE"],
            )

        statement_types: list[str] = []
        max_severity = Severity.LOW
        should_block = False

        for statement in parsed:
            stmt_type = self._classify_statement(statement)
            if stmt_type:
                statement_types.append(stmt_type)

                if stmt_type in _DESTRUCTIVE_KEYWORDS:
                    should_block = True
                    max_severity = (
                        Severity.CRITICAL
                        if stmt_type in {"DROP", "TRUNCATE"}
                        else Severity.HIGH
                    )
                elif stmt_type in _WRITE_KEYWORDS:
                    if max_severity == Severity.LOW:
                        max_severity = Severity.MEDIUM

        if should_block:
            return SQLAnalysisResult(
                verdict=VerdictType.BLOCK,
                severity=max_severity,
                reasoning=f"AST analysis detected destructive operations: {statement_types}",
                statement_types=statement_types,
            )

        if not statement_types:
            return SQLAnalysisResult(
                verdict=VerdictType.ESCALATE,
                severity=Severity.MEDIUM,
                reasoning="Could not determine SQL statement type — escalating to Tier 2",
                statement_types=[],
            )

        has_only_safe = all(st in _SAFE_KEYWORDS for st in statement_types)
        if has_only_safe:
            return SQLAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning=f"Read-only SQL operations: {statement_types}",
                statement_types=statement_types,
            )

        return SQLAnalysisResult(
            verdict=VerdictType.ESCALATE,
            severity=max_severity,
            reasoning=f"Write operations detected, escalating for review: {statement_types}",
            statement_types=statement_types,
        )

    def _classify_statement(self, statement: Statement) -> str | None:
        """Extract the primary operation type from a parsed SQL statement."""
        all_known = _DESTRUCTIVE_KEYWORDS | _WRITE_KEYWORDS | _SAFE_KEYWORDS

        stmt_type = statement.get_type()
        if stmt_type and stmt_type.upper() in all_known:
            return stmt_type.upper()

        for token in statement.flatten():
            if token.ttype in (DML, DDL, Keyword):
                val = token.value.upper().strip()
                if val in all_known:
                    return val
        return None
