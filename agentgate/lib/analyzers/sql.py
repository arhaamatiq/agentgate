"""SQL static analysis using sqlparse AST.

Three-pass approach:
  1. Fast string match for destructive keywords and dangerous SQL patterns.
     String literals are stripped before destructive-keyword scanning to prevent
     false positives on quoted text like SELECT 'DROP TABLE'.
  2. Full AST parse to catch obfuscation (e.g. comments, mixed case, concatenation).
  3. Post-AST indicator scan for dangerous patterns the AST naively classified as
     safe SELECT statements (UNION, DECLARE, etc.).
     Standalone information_schema queries are exempted as legitimate introspection.

Also provides table name extraction for scope-based resource checking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import unquote

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
_WRITE_KEYWORDS: set[str] = {"INSERT", "UPDATE", "CREATE", "MERGE", "UPSERT", "REPLACE", "REFRESH"}
_SAFE_KEYWORDS: set[str] = {"SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "WITH"}

_FAST_DESTRUCTIVE_RE = re.compile(
    r"\b(DROP|TRUNCATE|DELETE\s+FROM|ALTER\s+TABLE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)

_COMMENT_OBFUSCATION_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_STRING_LITERAL_RE = re.compile(r"'[^']*'")

# ---------------------------------------------------------------------------
# Dangerous SQL patterns — real agent misbehavior, NOT web injection fragments.
# Each tuple: (compiled regex, human description, severity).
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    # ---- UNION-based data exfiltration ----
    (re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
     "UNION SELECT exfiltration", Severity.HIGH),

    # ---- Execution primitives ----
    (re.compile(r"\bEXEC\s*\(", re.IGNORECASE),
     "Dynamic SQL execution (EXEC())", Severity.CRITICAL),
    (re.compile(r"\bEXEC\s+\w+", re.IGNORECASE),
     "Stored procedure execution (EXEC)", Severity.HIGH),
    (re.compile(r"\bEXECUTE\s+", re.IGNORECASE),
     "SQL execution (EXECUTE)", Severity.CRITICAL),
    (re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
     "OS command execution (xp_cmdshell)", Severity.CRITICAL),
    (re.compile(r"\bsp_executesql\b", re.IGNORECASE),
     "Dynamic SQL execution (sp_executesql)", Severity.CRITICAL),
    (re.compile(r"\bxp_\w+\b", re.IGNORECASE),
     "Extended stored procedure (xp_)", Severity.CRITICAL),
    (re.compile(r"\bDECLARE\s+@", re.IGNORECASE),
     "Variable declaration injection (DECLARE @)", Severity.HIGH),

    # ---- File exfiltration / write ----
    (re.compile(r"\bLOAD_FILE\s*\(", re.IGNORECASE),
     "SQL file read (LOAD_FILE)", Severity.CRITICAL),
    (re.compile(r"\bINTO\s+OUTFILE\b", re.IGNORECASE),
     "SQL file write (INTO OUTFILE)", Severity.CRITICAL),
    (re.compile(r"\bINTO\s+DUMPFILE\b", re.IGNORECASE),
     "SQL file write (INTO DUMPFILE)", Severity.CRITICAL),

    # ---- Stacked queries with dangerous follow-on ----
    (re.compile(
        r";\s*(?:DROP|DELETE|TRUNCATE|ALTER|EXEC|EXECUTE|DECLARE|GRANT|REVOKE|CREATE)\b",
        re.IGNORECASE,
    ), "Stacked query with dangerous operation", Severity.CRITICAL),

    # ---- Hex-encoded payload as primary content ----
    (re.compile(r"^\s*0x[0-9a-fA-F]{16,}"),
     "Hex-encoded payload", Severity.HIGH),
]

# ---------------------------------------------------------------------------
# Post-AST injection indicators — checked AFTER the AST says "safe SELECT".
# ---------------------------------------------------------------------------
_POST_AST_INDICATORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bUNION\b", re.IGNORECASE), "UNION keyword"),
    (re.compile(r"@\w+\s*="), "@variable assignment"),
    (re.compile(r"@@\w+"), "@@system variable access"),
    (re.compile(r"\bDECLARE\b", re.IGNORECASE), "DECLARE keyword"),
    (re.compile(r"\binformation_schema\b", re.IGNORECASE), "information_schema access"),
    (re.compile(r"\bsyscolumns\b", re.IGNORECASE), "syscolumns system table"),
    (re.compile(r"\bsysobjects\b", re.IGNORECASE), "sysobjects system table"),
    (re.compile(r"\bsys\.\w+", re.IGNORECASE), "sys.* system catalog"),
    (re.compile(r"\bmysql\.\w+", re.IGNORECASE), "mysql.* system catalog"),
    (re.compile(r"\bLOAD_FILE\b", re.IGNORECASE), "LOAD_FILE function"),
    (re.compile(r"\bINTO\s+(?:OUT|DUMP)FILE\b", re.IGNORECASE), "INTO OUTFILE/DUMPFILE"),
    (re.compile(r"\bINTO\s+TEMP\b", re.IGNORECASE), "INTO TEMP table"),
    (re.compile(r"\bEXEC\s*[\s(]", re.IGNORECASE), "EXEC keyword"),
]

# Indicators that are safe when they are the ONLY indicator in a well-formed SELECT.
_EXEMPT_LONE_INDICATORS: frozenset[str] = frozenset({
    "information_schema access",
})

_SQL_STARTERS: set[str] = {
    "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
    "WITH", "EXPLAIN", "SHOW", "DESCRIBE", "TRUNCATE", "GRANT", "REVOKE",
    "SET", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "MERGE",
    "CALL", "EXEC", "EXECUTE", "USE", "DECLARE", "IF", "WHILE",
    "REPLACE", "UPSERT", "VALUES", "TABLE", "INDEX", "VIEW",
    "REFRESH",
}

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


class SQLAnalyzer:
    """Analyzes SQL statements for destructive operations and injection patterns.

    Pass 1 (fast): Regex scan for destructive keywords + injection fragment patterns.
    Pass 2 (AST): Full sqlparse AST walk for obfuscated or multi-statement SQL.
    Pass 3 (post-AST): Injection indicator scan on statements the AST called safe.
    """

    DESTRUCTIVE_KEYWORDS: ClassVar[set[str]] = _DESTRUCTIVE_KEYWORDS
    WRITE_KEYWORDS: ClassVar[set[str]] = _WRITE_KEYWORDS

    # Regex for extracting table references from SQL.
    _TABLE_FROM_JOIN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:FROM|JOIN)\s+`?(\w+)`?(?:\s*\.\s*`?(\w+)`?)?",
        re.IGNORECASE,
    )
    _TABLE_INTO_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bINTO\s+`?(\w+)`?(?:\s*\.\s*`?(\w+)`?)?",
        re.IGNORECASE,
    )
    _TABLE_UPDATE_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bUPDATE\s+`?(\w+)`?(?:\s*\.\s*`?(\w+)`?)?",
        re.IGNORECASE,
    )

    # WITH [RECURSIVE] name AS (...) — first CTE
    _CTE_NAME_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bWITH\s+(?:RECURSIVE\s+)?(\w+)\s+AS\s*\(",
        re.IGNORECASE,
    )
    # Comma-separated subsequent CTEs: ), name AS (
    _CTE_CONTINUATION_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\)\s*,\s*(\w+)\s+AS\s*\(",
        re.IGNORECASE,
    )

    _NON_TABLE_WORDS: ClassVar[frozenset[str]] = frozenset({
        "SELECT", "WHERE", "SET", "VALUES", "DUAL", "OUTFILE",
        "DUMPFILE", "TEMP", "TEMPORARY", "LOCAL", "TABLE",
    })

    def extract_tables(self, sql: str) -> list[str]:
        """Extract referenced table names from a SQL query string.

        Uses regex over comment-stripped, literal-stripped SQL to find table
        references in FROM, JOIN, INTO, and UPDATE clauses. CTE aliases
        (WITH name AS) are excluded since they are query-local, not real tables.
        """
        if not sql or not sql.strip():
            return []

        cleaned = _COMMENT_OBFUSCATION_RE.sub("", sql)
        cleaned = _STRING_LITERAL_RE.sub("''", cleaned)

        cte_names: set[str] = set()
        for m in self._CTE_NAME_RE.finditer(cleaned):
            cte_names.add(m.group(1).lower())
        for m in self._CTE_CONTINUATION_RE.finditer(cleaned):
            cte_names.add(m.group(1).lower())

        tables: set[str] = set()

        for pattern in (self._TABLE_FROM_JOIN_RE, self._TABLE_INTO_RE, self._TABLE_UPDATE_RE):
            for m in pattern.finditer(cleaned):
                schema_or_table = m.group(1)
                table = m.group(2) if m.group(2) else schema_or_table
                table_lower = table.lower()
                if table.upper() not in self._NON_TABLE_WORDS and table_lower not in cte_names:
                    tables.add(table_lower)

        return sorted(tables)

    def analyze(self, sql: str) -> SQLAnalysisResult:
        """Analyze a SQL string and return a verdict."""
        if not sql or not sql.strip():
            return SQLAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="Empty SQL statement",
                statement_types=[],
            )

        sql = self._preprocess(sql)

        fast_result = self._fast_pass(sql)
        if fast_result is not None:
            return fast_result

        return self._ast_pass(sql)

    # ------------------------------------------------------------------
    # Preprocessing
    # ------------------------------------------------------------------

    def _preprocess(self, sql: str) -> str:
        """Normalize the input: URL-decode, resolve \\x escapes, strip null bytes."""
        decoded = unquote(unquote(sql))
        decoded = _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
        decoded = decoded.replace("\x00", "")
        return decoded

    # ------------------------------------------------------------------
    # Pass 1 — fast regex (synchronous, no API calls)
    # ------------------------------------------------------------------

    def _fast_pass(self, sql: str) -> SQLAnalysisResult | None:
        """Pass 1: fast regex for destructive SQL AND injection fragment patterns."""
        stripped = _COMMENT_OBFUSCATION_RE.sub("", sql)

        # Strip string literals before destructive-keyword check to prevent
        # false positives on quoted text like SELECT 'DROP TABLE' AS col
        no_literals = _STRING_LITERAL_RE.sub("''", stripped)
        match = _FAST_DESTRUCTIVE_RE.search(no_literals)
        if match:
            keyword = match.group(1).split()[0].upper()
            return SQLAnalysisResult(
                verdict=VerdictType.BLOCK,
                severity=Severity.CRITICAL if keyword in {"DROP", "TRUNCATE"} else Severity.HIGH,
                reasoning=f"Destructive SQL operation detected: {keyword}",
                statement_types=[keyword],
            )

        # Injection patterns check the full (comment-stripped) SQL — these
        # patterns are designed for injection context, not for string content
        for pattern, description, severity in _INJECTION_PATTERNS:
            if pattern.search(stripped):
                return SQLAnalysisResult(
                    verdict=VerdictType.BLOCK,
                    severity=severity,
                    reasoning=f"Injection pattern detected: {description}",
                    statement_types=[description],
                )

        return None

    # ------------------------------------------------------------------
    # Pass 2 — AST analysis
    # ------------------------------------------------------------------

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
            indicator = self._injection_indicator_scan(sql)
            if indicator is not None:
                return SQLAnalysisResult(
                    verdict=VerdictType.BLOCK,
                    severity=Severity.HIGH,
                    reasoning=f"Injection indicator in statement classified as safe: {indicator}",
                    statement_types=statement_types,
                )
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

    # ------------------------------------------------------------------
    # Pass 3 — post-AST injection indicator scan
    # ------------------------------------------------------------------

    def _injection_indicator_scan(self, sql: str) -> str | None:
        """Check a statement the AST classified as safe for injection indicators.

        Collects all matching indicators and applies exemption logic:
        standalone information_schema queries (legitimate introspection)
        are allowed when no other injection indicators are present.
        """
        found: list[str] = []
        for pattern, name in _POST_AST_INDICATORS:
            if pattern.search(sql):
                found.append(name)

        if found:
            if all(ind in _EXEMPT_LONE_INDICATORS for ind in found):
                return None
            return found[0]

        fragment = self._looks_like_fragment(sql)
        if fragment is not None:
            return fragment

        return None

    def _looks_like_fragment(self, sql: str) -> str | None:
        """Detect whether the SQL is an injection fragment rather than a complete query."""
        stripped = sql.strip()
        if not stripped:
            return None

        first_word_match = re.match(r"^(\w+)", stripped)
        if first_word_match:
            first_word = first_word_match.group(1).upper()
            if first_word not in _SQL_STARTERS:
                return f"Does not start with SQL keyword (starts with '{first_word}')"
        else:
            return f"Starts with non-keyword character: {stripped[0]!r}"

        tokens = stripped.split()
        if len(tokens) <= 1:
            return "Bare SQL keyword without query structure"

        if re.match(r"^\d+\s*;", stripped):
            return "Numeric prefix with stacked query"

        return None

    # ------------------------------------------------------------------
    # AST helpers
    # ------------------------------------------------------------------

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
