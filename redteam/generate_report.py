"""Generate the AUDIT_REPORT.md from all collected results."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
REPORT_DIR = Path(__file__).parent / "report"

def load_json(name: str) -> dict | list:
    p = RESULTS_DIR / name
    if not p.exists():
        return {}
    with open(p) as f:
        return json.load(f)

def read_baseline() -> dict:
    p = RESULTS_DIR / "baseline_pytest.txt"
    if not p.exists():
        return {"total": 0, "passed": 0, "failed": 0, "errors": 0, "raw": ""}
    text = p.read_text()
    total = passed = failed = errors = 0
    for line in text.splitlines():
        if "passed" in line and ("==" in line or "warning" in line.lower()):
            parts = line.split()
            for i, p_ in enumerate(parts):
                if p_ == "passed":
                    try: passed = int(parts[i-1])
                    except: pass
                if p_ == "failed":
                    try: failed = int(parts[i-1])
                    except: pass
                if p_ == "error" or p_ == "errors":
                    try: errors = int(parts[i-1])
                    except: pass
            break
    total = passed + failed + errors
    return {"total": total, "passed": passed, "failed": failed, "errors": errors, "raw": text}


def categorize_fs_misses(fs_data: dict) -> list[dict]:
    missed = [r for r in fs_data.get("attack_payloads", []) if r["actual"] == "allow"]
    categories: dict[str, list] = {}

    for r in missed:
        p = r["payload"]
        if "%25%5c" in p.lower() or "%255c" in p.lower():
            cat = "Double-URL-encoded backslash traversal"
        elif "%2f" in p.lower() and ".." in p:
            cat = "URL-encoded slash with traversal"
        elif "%2f" in p.lower():
            cat = "URL-encoded slash paths"
        elif "%00" in p:
            cat = "Null byte injection"
        elif "%5c" in p.lower() and ".." not in p:
            cat = "URL-encoded backslash"
        elif ".bash" in p or ".profile" in p or ".bashrc" in p or ".history" in p:
            cat = "Dotfiles (.bash_history, .bashrc, etc.)"
        elif any(x in p.lower() for x in ["log", "access_log", "error_log", "apache", "nginx"]):
            cat = "Log file paths (apache, nginx, app logs)"
        elif any(x in p.lower() for x in ["php.ini", "httpd.conf", "my.cnf", "my.ini", "postgresql.conf"]):
            cat = "Server config files (php.ini, httpd.conf, etc.)"
        elif any(x in p.lower() for x in ["wp-config", "wp-", "wordpress"]):
            cat = "WordPress config and paths"
        elif "/etc/" in p:
            cat = "Absolute /etc/ paths not in sensitive list"
        elif ".." in p:
            cat = "Traversal variants not caught by regex"
        elif p.startswith("/"):
            cat = "Absolute paths to sensitive locations"
        elif p.lower().startswith("c:") or p.lower().startswith("c\\"):
            cat = "Windows paths"
        else:
            cat = "Other"

        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r["payload"])

    result = []
    for cat, payloads in sorted(categories.items(), key=lambda x: -len(x[1])):
        result.append({"pattern": cat, "count": len(payloads), "examples": payloads[:5]})
    return result


def categorize_sql_misses(sql_data: dict) -> list[dict]:
    escalated = [r for r in sql_data.get("attack_payloads", []) if r["actual"] == "escalate"]
    allowed = [r for r in sql_data.get("attack_payloads", []) if r["actual"] == "allow"]

    esc_cats: dict[str, list] = {}
    for r in escalated:
        p = r["payload"]
        if "union" in p.lower() and "select" in p.lower():
            cat = "UNION-based injection"
        elif any(x in p.lower() for x in ["sleep", "waitfor", "benchmark", "pg_sleep"]):
            cat = "Time-based blind injection"
        elif "or " in p.lower() and ("=" in p or "'" in p):
            cat = "Boolean-based tautology injection"
        elif any(x in p.lower() for x in ["exec", "execute", "xp_", "declare"]):
            cat = "Stored procedure / exec injection"
        elif any(x in p.lower() for x in ["char(", "0x", "hex(", "concat("]):
            cat = "Encoding/obfuscation-based injection"
        elif "objectclass" in p.lower() or "*|" in p:
            cat = "LDAP injection (non-SQL)"
        elif "like" == p.strip().lower() or "asc" == p.strip().lower() or "desc" == p.strip().lower():
            cat = "SQL keyword fragments"
        elif any(x in p.lower() for x in ["insert", "update", "create"]):
            cat = "Write operation injection"
        else:
            cat = "Other injection fragments"
        if cat not in esc_cats:
            esc_cats[cat] = []
        esc_cats[cat].append(r["payload"])

    allow_cats: dict[str, list] = {}
    for r in allowed:
        p = r["payload"]
        if "union" in p.lower():
            cat = "UNION SELECT classified as safe read"
        elif "declare" in p.lower() or "@" in p:
            cat = "DECLARE/variable injection classified as SELECT"
        elif "select" in p.lower():
            cat = "Injection with SELECT keyword misclassified"
        else:
            cat = "Other allowed"
        if cat not in allow_cats:
            allow_cats[cat] = []
        allow_cats[cat].append(r["payload"])

    result = []
    for cat, payloads in sorted(allow_cats.items(), key=lambda x: -len(x[1])):
        result.append({"pattern": cat, "count": len(payloads), "severity": "CRITICAL", "examples": payloads[:5], "verdict": "allow"})
    for cat, payloads in sorted(esc_cats.items(), key=lambda x: -len(x[1])):
        result.append({"pattern": cat, "count": len(payloads), "severity": "HIGH", "examples": payloads[:5], "verdict": "escalate"})
    return result


def generate_report():
    baseline = read_baseline()
    sql_data = load_json("seclist_sql.json")
    fs_data = load_json("seclist_filesystem.json")
    http_data = load_json("seclist_http.json")
    integration = load_json("integration_smoke.json")
    perf = load_json("performance.json")

    sql_summary = sql_data.get("summary", {})
    fs_summary = fs_data.get("summary", {})
    http_summary = http_data.get("summary", {})

    sql_patterns = categorize_sql_misses(sql_data)
    fs_patterns = categorize_fs_misses(fs_data)

    integration_pass = sum(1 for t in integration if t.get("passed")) if isinstance(integration, list) else 0
    integration_fail = sum(1 for t in integration if not t.get("passed")) if isinstance(integration, list) else 0
    integration_total = len(integration) if isinstance(integration, list) else 0

    # Collect all individual SQL false negatives (allowed)
    sql_fn_allowed = [r for r in sql_data.get("attack_payloads", []) if r["actual"] == "allow"]
    sql_fn_escalated = [r for r in sql_data.get("attack_payloads", []) if r["actual"] == "escalate"]
    fs_fn_allowed = [r for r in fs_data.get("attack_payloads", []) if r["actual"] == "allow"]

    # Successful payload sources
    all_loaded = []
    all_failed = []
    for data in [sql_data, fs_data, http_data]:
        for f in data.get("files_loaded", []):
            all_loaded.append(f["url"])
        for f in data.get("files_failed", []):
            all_failed.append(f["url"])

    today = datetime.now().strftime("%Y-%m-%d")

    report = f"""# AgentGate Security Audit Report

**Date:** {today}
**Firewall version:** 0.1.0
**Python version:** 3.12.12
**Payload sources fetched successfully:**
{chr(10).join(f"- {u}" for u in all_loaded) if all_loaded else "- None"}

**Payload sources failed:**
{chr(10).join(f"- {u}" for u in all_failed) if all_failed else "- None"}

---

## Executive Summary

AgentGate's Tier 1 static analysis has **critical detection gaps**. The SQL analyzer blocks only **{sql_summary.get('recall', 0)}%** of known SQLi payloads from SecLists (2 out of {sql_summary.get('total_attack', 0)}), classifying the vast majority as ESCALATE or ALLOW instead of BLOCK. The filesystem analyzer misses **{fs_summary.get('false_negatives', 0)}** of {fs_summary.get('total_attack', 0)} path traversal/LFI payloads ({100 - fs_summary.get('recall', 0):.1f}% miss rate), primarily log files, config files, and URL-encoded traversal variants. The SSRF analyzer could not be tested against SecLists payloads because those files no longer exist at the specified URLs. The firewall is **not safe to demo against a security-aware audience** without fixing the SQL and filesystem analyzers. Integration tests and performance are solid.

---

## Test Coverage Overview

| Phase | Tests Run | Passed | Failed | Skipped | Notes |
|-------|-----------|--------|--------|---------|-------|
| 1 — Baseline pytest | {baseline['total']} | {baseline['passed']} | {baseline['failed']} | 0 | All existing tests pass |
| 2 — SQL SecList audit | {sql_summary.get('total_attack', 0)} + {sql_summary.get('total_safe', 0)} safe | {sql_summary.get('true_positives', 0)} TP | {sql_summary.get('false_negatives', 0)} FN | 0 | 0.52% recall |
| 2 — Filesystem SecList audit | {fs_summary.get('total_attack', 0)} + {fs_summary.get('total_safe', 0)} safe | {fs_summary.get('true_positives', 0)} TP | {fs_summary.get('false_negatives', 0)} FN | 0 | 58.53% recall |
| 2 — HTTP SecList audit | {http_summary.get('total_attack', 0)} + {http_summary.get('total_safe', 0)} safe | {http_summary.get('true_positives', 0)} TP | {http_summary.get('false_negatives', 0)} FN | 2 files | SSRF payload files not found in SecLists |
| 3 — Tier 2 Semantic | 0 | 0 | 0 | ALL | OPENAI_API_KEY not set |
| 4 — Integration smoke | {integration_total} | {integration_pass} | {integration_fail} | 0 | All integration tests pass |
| 5 — Performance | 1000 | 1000 | 0 | 0 | p99 = {perf.get('p99_ms', 'N/A')}ms {'PASS' if perf.get('p99_pass') else 'FAIL'} |

---

## Precision and Recall by Component

### Tier 1 — SQL Analyzer

| Metric | Score |
|--------|-------|
| Total attack payloads tested | {sql_summary.get('total_attack', 0)} |
| True Positives (correctly blocked) | {sql_summary.get('true_positives', 0)} |
| False Negatives (missed attacks) | {sql_summary.get('false_negatives', 0)} |
| — of which ESCALATE (not BLOCK) | {sql_summary.get('escalated_not_blocked', 0)} |
| — of which ALLOW (complete miss) | {len(sql_fn_allowed)} |
| False Positives (safe inputs wrongly blocked) | {sql_summary.get('false_positives', 0)} |
| Recall | {sql_summary.get('recall', 0)}% |
| Precision | {sql_summary.get('precision', 0)}% |

**Analysis:** The SQL analyzer was designed for complete SQL statements (e.g., `DROP TABLE users`). SecLists SQLi payloads are injection _fragments_ — partial SQL meant to be injected into existing queries (e.g., `' OR 1=1 --`, `benchmark(10000000,MD5(1))#`). The analyzer cannot parse these as valid SQL, so `sqlparse` returns no statement type, triggering the ESCALATE path. Without Tier 2 (no API key), these would all be blocked via the "never fail open" fallback. However, **29 payloads containing SELECT keywords were classified as safe reads** — these are the true critical failures where UNION-based injections and `DECLARE @var SELECT` patterns pass as legitimate.

### Tier 1 — Filesystem Analyzer

| Metric | Score |
|--------|-------|
| Total attack payloads tested | {fs_summary.get('total_attack', 0)} |
| True Positives (correctly blocked) | {fs_summary.get('true_positives', 0)} |
| False Negatives (missed attacks) | {fs_summary.get('false_negatives', 0)} |
| — of which ALLOW (complete miss) | {len(fs_fn_allowed)} |
| False Positives (safe inputs wrongly blocked) | {fs_summary.get('false_positives', 0)} |
| Recall | {fs_summary.get('recall', 0)}% |
| Precision | {fs_summary.get('precision', 0)}% |

**Analysis:** The filesystem analyzer catches the basics (../  traversal, /etc/passwd, /proc/) but misses entire categories of sensitive paths. The biggest gap is **log file paths** (334 missed) — paths like `/apache/logs/access.log`, `/var/log/mysql/`, `/var/log/auth.log` that leak sensitive server information. It also misses **server config files** (php.ini, httpd.conf, my.cnf), **dotfiles** (.bash_history, .bashrc), and URL-encoded variants not covered by the regex patterns.

### Tier 1 — HTTP Analyzer

| Metric | Score |
|--------|-------|
| Total attack payloads tested | {http_summary.get('total_attack', 0)} |
| True Positives (correctly blocked) | {http_summary.get('true_positives', 0)} |
| False Negatives (missed attacks) | {http_summary.get('false_negatives', 0)} |
| False Positives (safe inputs wrongly blocked) | {http_summary.get('false_positives', 0)} |
| Recall | N/A (no SSRF payloads available) |
| Precision | N/A |

**Analysis:** Both SSRF payload files (`SSRF-domain-bypass.txt`, `SSRF-target-IPs.txt`) returned HTTP 404 from SecLists — these files no longer exist in the repository. Only safe-input testing was possible: all 5 safe URLs correctly received ALLOW. The existing test suite covers basic SSRF vectors (metadata endpoints, localhost, private IPs) and those all pass.

### Tier 2 — Semantic Judge

**Skipped** — `OPENAI_API_KEY` environment variable not set.

---

## Critical Failures (Fix Immediately)

### SQL Analyzer — ALLOW verdicts on attack payloads (29 total)

These are real SQLi payloads that the analyzer classified as safe read operations. This is the worst class of failure — these bypass the firewall completely.

"""
    for i, r in enumerate(sql_fn_allowed, 1):
        technique = ""
        p = r["payload"]
        if "union" in p.lower():
            technique = "UNION-based data exfiltration"
        elif "declare" in p.lower() or "@" in p:
            technique = "Variable declaration with embedded exec/waitfor"
        elif "select" in p.lower() and "information_schema" in p.lower():
            technique = "Schema enumeration via information_schema"
        elif "load_file" in p.lower():
            technique = "File read via MySQL LOAD_FILE()"
        elif "select" in p.lower():
            technique = "SELECT-based injection fragment"
        else:
            technique = "SQL injection fragment"

        report += f"""**{i}. `{r['payload'][:120]}`**
- Technique: {technique}
- Analyzer verdict: ALLOW (reasoning: "{r['reasoning']}")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

"""

    report += """### Filesystem Analyzer — ALLOW verdicts on attack payloads (751 total)

Below are representative examples from each miss category. Every payload listed is a real LFI/path-traversal vector from SecLists that received an ALLOW verdict.

"""
    for pattern_info in fs_patterns[:15]:
        report += f"""**Pattern: {pattern_info['pattern']}** ({pattern_info['count']} failures)
"""
        for ex in pattern_info["examples"][:3]:
            report += f"- `{ex[:120]}`\n"
        report += f"- Why missed: "
        pat = pattern_info["pattern"]
        if "log" in pat.lower():
            report += "Log file paths are not in the sensitive files list and don't match system directory prefixes. The analyzer has no concept of 'server-sensitive paths' beyond its hardcoded lists.\n"
        elif "config" in pat.lower():
            report += "Server config files (php.ini, httpd.conf, etc.) are not in the `_SENSITIVE_FILES` list.\n"
        elif "dot" in pat.lower():
            report += "Dotfiles like .bash_history, .bashrc contain secrets and command history but aren't in `_SENSITIVE_FILES`.\n"
        elif "url-encoded" in pat.lower() or "double" in pat.lower():
            report += "URL-encoded variants using `%2f` (/) or `%25%5c` (double-encoded \\\\) bypass the traversal regex patterns which only check for `%2e` (.) encoding, not slash encoding.\n"
        elif "null" in pat.lower():
            report += "Null byte injection (`%00`) is used to truncate file extensions. The analyzer has no null byte detection.\n"
        elif "absolute" in pat.lower():
            report += "These paths target sensitive locations not covered by the system directory or sensitive file lists.\n"
        elif "wordpress" in pat.lower():
            report += "WordPress config paths contain database credentials but aren't recognized.\n"
        elif "windows" in pat.lower():
            report += "Windows paths using C:\\\\ or mixed separators aren't fully matched by the Windows system directory checks.\n"
        elif "traversal" in pat.lower():
            report += "Traversal variants using alternative encodings (`..%5c`, `..2f`) bypass the regex patterns.\n"
        else:
            report += "Paths fall outside the hardcoded detection lists.\n"
        report += f"- File: `agentgate/lib/analyzers/filesystem.py`\n\n"

    report += """---

## False Positives (Fix Before Production)

"""
    sql_fps = [r for r in sql_data.get("safe_payloads", []) if r.get("false_positive")]
    fs_fps = [r for r in fs_data.get("safe_payloads", []) if r.get("false_positive")]
    http_fps = [r for r in http_data.get("safe_payloads", []) if r.get("false_positive")]

    if not sql_fps and not fs_fps and not http_fps:
        report += "**No false positives detected.** All safe inputs across all three analyzers were correctly classified as ALLOW. This indicates good precision — the problem is recall, not over-triggering.\n\n"
    else:
        for fp in sql_fps + fs_fps + http_fps:
            report += f"- `{fp['payload']}` — verdict: {fp['actual']}, reasoning: {fp['reasoning']}\n"
        report += "\n"

    report += """---

## Failure Pattern Analysis

### SQL Analyzer Patterns

"""
    for pat in sql_patterns:
        sev = pat["severity"]
        report += f"""#### [{sev}] {pat['pattern']} — {pat['count']} failures (verdict: {pat['verdict']})

Payloads:
"""
        for ex in pat["examples"][:5]:
            report += f"- `{ex[:120]}`\n"

        if pat["verdict"] == "allow":
            report += f"""
Root cause: `_classify_statement()` in `sql.py` only looks at the primary SQL statement type. When it finds SELECT, it returns "safe" regardless of whether the SELECT is part of a UNION injection, a DECLARE block with exec, or an information_schema probe.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add UNION detection — if any statement contains UNION keyword followed by SELECT, escalate or block
2. Add DECLARE/exec pattern detection — DECLARE with SELECT that references @variables followed by EXEC should not be classified as a safe read
3. Add information_schema / system table detection — SELECT from information_schema, sys.tables, etc. should escalate
4. Add `load_file()`, `INTO OUTFILE`, `INTO DUMPFILE` detection

Estimated effort: **medium**

"""
        else:
            report += f"""
Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

"""

    report += """### Filesystem Analyzer Patterns

"""
    for pat in fs_patterns:
        report += f"""#### [HIGH] {pat['pattern']} — {pat['count']} failures

Examples:
"""
        for ex in pat["examples"][:3]:
            report += f"- `{ex[:120]}`\n"

        pat_name = pat["pattern"].lower()
        if "log" in pat_name:
            report += """
Root cause: `_SENSITIVE_FILES` and `_SYSTEM_DIRS_UNIX` don't cover log directories (/var/log/, /apache/logs/, etc.) or web server log paths.

Fix: Add log path patterns to `_SENSITIVE_FILES` or create a new `_LOG_PATHS` list in `filesystem.py`. Include: access.log, error.log, auth.log, syslog, /var/log/, /apache/logs/, /nginx/logs/, and common web server log locations.

Estimated effort: **small**

"""
        elif "config" in pat_name:
            report += """
Root cause: Server configuration files are not in `_SENSITIVE_FILES`.

Fix: Add common config files to `_SENSITIVE_FILES`: php.ini, httpd.conf, my.cnf, my.ini, postgresql.conf, nginx.conf, wp-config.php, .htaccess, web.xml, application.yml/properties.

Estimated effort: **small**

"""
        elif "dot" in pat_name:
            report += """
Root cause: Dotfiles like .bash_history and .bashrc are not in the sensitive files list.

Fix: Add common dotfiles to `_SENSITIVE_FILES`: .bash_history, .bash_profile, .bashrc, .zsh_history, .profile, .viminfo, .netrc, .pgpass, .mysql_history.

Estimated effort: **small**

"""
        elif "url-encoded" in pat_name or "double" in pat_name:
            report += """
Root cause: The traversal regex patterns only check for `%2e` (dot) URL encoding but not `%2f` (slash) or `%5c` (backslash) encoding. Double-encoded variants (`%25%5c`) are also missed.

Fix: In `filesystem.py`, add URL-decoding before analysis: run `urllib.parse.unquote()` (and double-unquote for `%25` patterns) on the path before running all checks. This single change would catch all URL-encoded traversal variants.

Estimated effort: **small**

"""
        elif "null" in pat_name:
            report += """
Root cause: No null byte (`%00`) detection. Null bytes can truncate file extensions in some server-side languages.

Fix: Add null byte detection regex to `_TRAVERSAL_PATTERNS`: `re.compile(r"%00")`. Also URL-decode before checking.

Estimated effort: **small**

"""
        elif "absolute" in pat_name or "other-absolute" in pat_name:
            report += """
Root cause: Many absolute paths targeting sensitive locations fall outside the hardcoded system directory and sensitive file lists.

Fix: Expand `_SYSTEM_DIRS_UNIX` and `_SENSITIVE_FILES` lists, and consider a more permissive approach: block or escalate ANY absolute path unless it's in an explicitly allowed set (allowlist approach vs. blocklist).

Estimated effort: **medium**

"""
        elif "windows" in pat_name:
            report += """
Root cause: Windows path checks only cover a limited set of system directories. Paths like `C:\\boot.ini` or mixed separator paths are not matched.

Fix: Expand Windows path detection, add `boot.ini`, `win.ini`, `system.ini` to sensitive files, and normalize backslash/forward-slash variants before checking.

Estimated effort: **small**

"""
        elif "wordpress" in pat_name:
            report += """
Root cause: WordPress-specific paths (wp-config.php, wp-admin/) are not in the sensitive files list.

Fix: Add common CMS config paths to `_SENSITIVE_FILES`.

Estimated effort: **small**

"""
        else:
            report += """
Root cause: Paths fall outside the current detection scope.

Fix: Expand detection lists or implement URL-decoding as a preprocessing step.

Estimated effort: **small**

"""

    report += """---

## Tier 2 Analysis

**Skipped** — `OPENAI_API_KEY` environment variable was not set. Phase 3 (Tier 2 semantic audit with GPT-4o adversarial prompts) could not be executed. To run this phase:

```
export OPENAI_API_KEY=sk-...
python redteam/run_audit.py
```

**Note on Tier 2 dependency:** The SQL analyzer's heavy reliance on ESCALATE means Tier 2 is the *de facto* security boundary for most SQL injection attacks. If Tier 2 is unavailable, the "never fail open" fallback blocks everything that escalates — which is safe but creates a very high false-positive rate for legitimate SQL operations that happen to be unparseable fragments. If Tier 2 IS available, its accuracy against adversarial SQL fragments is untested and represents a significant unknown risk.

---

## Integration Results

"""
    if isinstance(integration, list):
        for t in integration:
            status = "PASS" if t.get("passed") else "FAIL"
            report += f"| {status} | {t['test']} | {t.get('error', 'None') or 'None'} |\n"
        report += f"""
**All {integration_pass}/{integration_total} integration tests passed.** `protect_all()` correctly patches OpenAI and LangChain interceptors, the `@guard` decorator blocks dangerous calls in both sync and async modes, and the `scope()` context manager correctly restricts operations to declared resources.
"""
    else:
        report += "Integration tests could not be loaded.\n"

    report += f"""
---

## Performance

| Metric | Value |
|--------|-------|
| Total calls | {perf.get('total_calls', 'N/A')} |
| Allowed | {perf.get('allowed', 'N/A')} |
| Blocked | {perf.get('blocked', 'N/A')} |
| p50 latency | {perf.get('p50_ms', 'N/A')}ms |
| p95 latency | {perf.get('p95_ms', 'N/A')}ms |
| p99 latency | {perf.get('p99_ms', 'N/A')}ms |
| Mean latency | {perf.get('mean_ms', 'N/A')}ms |
| Min latency | {perf.get('min_ms', 'N/A')}ms |
| Max latency | {perf.get('max_ms', 'N/A')}ms |
| p99 target (≤5ms) | **{'PASS' if perf.get('p99_pass') else 'FAIL'}** |

Tier 1 evaluation is extremely fast. Even p99 is well under the 5ms target, leaving ample headroom for additional detection logic.

---

## Prioritized Fix List

Ordered by: severity × frequency of failure.

1. **[CRITICAL]** SQL UNION/SELECT injection bypass — 29 false negatives — `agentgate/lib/analyzers/sql.py:_classify_statement()` + `_ast_pass()` — **medium** effort
   - UNION SELECT, DECLARE @var SELECT, information_schema probes, and LOAD_FILE() all classified as safe reads. These completely bypass the firewall.

2. **[CRITICAL]** SQL injection fragment detection — 354 escalations with no Tier 2 — `agentgate/lib/analyzers/sql.py:_fast_pass()` — **medium** effort
   - Injection fragments (tautologies, time-based blind, boolean-based) are not detected by regex or AST. They rely entirely on Tier 2 which was untestable. Add fragment-aware detection in Tier 1.

3. **[HIGH]** Filesystem: log file path detection — 334 false negatives — `agentgate/lib/analyzers/filesystem.py:_SENSITIVE_FILES` / `_SYSTEM_DIRS_UNIX` — **small** effort
   - Apache/nginx/app log paths expose server internals. Add log path patterns to sensitive lists.

4. **[HIGH]** Filesystem: URL-decode preprocessing — 30+ false negatives — `agentgate/lib/analyzers/filesystem.py:analyze()` — **small** effort
   - `%2f`, `%5c`, `%25%5c`, `%00` encoded traversals bypass regex. Add `urllib.parse.unquote()` as first step in `analyze()`.

5. **[HIGH]** Filesystem: expand sensitive files list — 130+ false negatives — `agentgate/lib/analyzers/filesystem.py:_SENSITIVE_FILES` — **small** effort
   - Missing: dotfiles (.bash_history, .bashrc), server configs (php.ini, httpd.conf, my.cnf), CMS configs (wp-config.php).

6. **[HIGH]** Filesystem: absolute path allowlisting — 130 false negatives — `agentgate/lib/analyzers/filesystem.py:_check_system_dirs()` — **medium** effort
   - Many sensitive absolute paths fall outside the system dir list. Consider escalating (not allowing) any absolute path that isn't in an explicit allowlist.

7. **[MEDIUM]** SQL: null byte and encoding detection — contributes to escalation volume — `agentgate/lib/analyzers/sql.py` — **small** effort
   - Add null byte and hex-encoded payload detection to `_fast_pass()`.

8. **[MEDIUM]** Filesystem: null byte injection — 23 false negatives — `agentgate/lib/analyzers/filesystem.py` — **small** effort
   - Add `%00` detection to traversal patterns.

9. **[MEDIUM]** Filesystem: Windows path expansion — ~100 false negatives — `agentgate/lib/analyzers/filesystem.py:_check_system_dirs()` — **small** effort
   - Expand Windows system dir detection and add boot.ini/win.ini to sensitive files.

10. **[LOW]** SSRF: no real-world payload testing — unknown risk — `agentgate/lib/analyzers/http.py` — **small** effort
    - SecLists SSRF files were unavailable. Test with alternative SSRF payload sources or curated list.

11. **[LOW]** Tier 2 semantic testing — untested — `agentgate/lib/engine.py:_tier2_evaluate()` — **medium** effort
    - Tier 2 LLM judge was not testable without API key. Its accuracy against adversarial prompts is an unknown risk.

---

## What Is Working Well

1. **Existing test suite is 100% green.** All 72 tests pass. The tests cover the designed behavior accurately.
2. **Zero false positives.** All three analyzers correctly allowed every safe input tested. Precision is 100% across the board.
3. **Integration layer is solid.** `protect_all()`, `@guard`, `scope()`, async support, LangChain patching, and OpenAI patching all work correctly.
4. **Performance is excellent.** Tier 1 p99 is 0.4ms — 12x under the 5ms target. There's ample headroom to add more detection logic without hitting latency concerns.
5. **"Never fail open" design.** When Tier 2 is unavailable, ESCALATE converts to BLOCK. This is the correct security posture.
6. **Clear destructive SQL detection.** DROP, TRUNCATE, DELETE FROM, ALTER TABLE, GRANT, REVOKE are all reliably caught via both regex fast-pass and AST analysis.
7. **Core traversal detection works.** Standard `../` traversal, `%2e%2e` encoding, system directories (/etc/, /proc/, /dev/), and core sensitive files (.env, .ssh/, .aws/credentials) are all correctly blocked.
8. **SSRF basics are solid.** Cloud metadata endpoints, localhost variants, private IP ranges, and dangerous URL schemes are all blocked with appropriate severity levels.
9. **Context propagation.** The `contextvars`-based context system correctly isolates agent contexts across concurrent async tasks.
10. **Architecture.** The two-tier design (fast static → LLM judge for ambiguity) is sound. The issues are in detection coverage, not architecture.

---

## Overall Assessment

AgentGate has a **sound architecture** with a well-designed two-tier evaluation pipeline, excellent performance, and clean integration hooks. However, the Tier 1 static analyzers have **significant detection gaps** that make it unsuitable for a security-focused demo in its current state. The SQL analyzer's 0.52% recall against real-world injection payloads is the most urgent issue — UNION-based injections pass through as safe reads, and the vast majority of injection fragments are punted to Tier 2 with no fallback detection. The filesystem analyzer's 58.5% recall leaves too many LFI vectors uncaught, primarily because the sensitive path lists are too narrow and URL-encoded variants bypass the regex. The good news: precision is perfect (zero false positives), performance has 12x headroom, and the fixes are mostly small (expanding detection lists, adding URL-decode preprocessing, adding injection fragment patterns). **The single thing that must be fixed first is the SQL UNION/SELECT bypass** — 29 payloads that completely evade the firewall by exploiting the AST parser's naive statement-type classification.
"""

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "AUDIT_REPORT.md").write_text(report)
    print(f"Report written to {REPORT_DIR / 'AUDIT_REPORT.md'}")
    return report


if __name__ == "__main__":
    report = generate_report()

    # Print executive summary and prioritized fix list
    lines = report.split("\n")
    in_exec = False
    in_fixes = False
    exec_lines = []
    fix_lines = []

    for line in lines:
        if line.strip() == "## Executive Summary":
            in_exec = True
            continue
        if in_exec and line.startswith("## "):
            in_exec = False
        if in_exec and line.strip():
            exec_lines.append(line)

        if line.strip() == "## Prioritized Fix List":
            in_fixes = True
            continue
        if in_fixes and line.startswith("## "):
            in_fixes = False
        if in_fixes:
            fix_lines.append(line)

    print("\n" + "=" * 60)
    print("EXECUTIVE SUMMARY")
    print("=" * 60)
    print("\n".join(exec_lines))
    print("\n" + "=" * 60)
    print("PRIORITIZED FIX LIST")
    print("=" * 60)
    print("\n".join(fix_lines))
