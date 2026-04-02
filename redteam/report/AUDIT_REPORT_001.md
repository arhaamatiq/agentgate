# AgentGate Security Audit Report

**Date:** 2026-03-27
**Firewall version:** 0.1.0
**Python version:** 3.12.12
**Payload sources fetched successfully:**
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt

**Payload sources failed:**
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-domain-bypass.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-target-IPs.txt

---

## Executive Summary

AgentGate's Tier 1 static analysis has **critical detection gaps**. The SQL analyzer blocks only **0.52%** of known SQLi payloads from SecLists (2 out of 385), classifying the vast majority as ESCALATE or ALLOW instead of BLOCK. The filesystem analyzer misses **751** of 1811 path traversal/LFI payloads (41.5% miss rate), primarily log files, config files, and URL-encoded traversal variants. The SSRF analyzer could not be tested against SecLists payloads because those files no longer exist at the specified URLs. The firewall is **not safe to demo against a security-aware audience** without fixing the SQL and filesystem analyzers. Integration tests and performance are solid.

---

## Test Coverage Overview

| Phase | Tests Run | Passed | Failed | Skipped | Notes |
|-------|-----------|--------|--------|---------|-------|
| 1 — Baseline pytest | 72 | 72 | 0 | 0 | All existing tests pass |
| 2 — SQL SecList audit | 385 + 6 safe | 2 TP | 383 FN | 0 | 0.52% recall |
| 2 — Filesystem SecList audit | 1811 + 5 safe | 1060 TP | 751 FN | 0 | 58.53% recall |
| 2 — HTTP SecList audit | 0 + 5 safe | 0 TP | 0 FN | 2 files | SSRF payload files not found in SecLists |
| 3 — Tier 2 Semantic | 0 | 0 | 0 | ALL | OPENAI_API_KEY not set |
| 4 — Integration smoke | 5 | 5 | 0 | 0 | All integration tests pass |
| 5 — Performance | 1000 | 1000 | 0 | 0 | p99 = 0.4048ms PASS |

---

## Precision and Recall by Component

### Tier 1 — SQL Analyzer

| Metric | Score |
|--------|-------|
| Total attack payloads tested | 385 |
| True Positives (correctly blocked) | 2 |
| False Negatives (missed attacks) | 383 |
| — of which ESCALATE (not BLOCK) | 354 |
| — of which ALLOW (complete miss) | 29 |
| False Positives (safe inputs wrongly blocked) | 0 |
| Recall | 0.52% |
| Precision | 100.0% |

**Analysis:** The SQL analyzer was designed for complete SQL statements (e.g., `DROP TABLE users`). SecLists SQLi payloads are injection _fragments_ — partial SQL meant to be injected into existing queries (e.g., `' OR 1=1 --`, `benchmark(10000000,MD5(1))#`). The analyzer cannot parse these as valid SQL, so `sqlparse` returns no statement type, triggering the ESCALATE path. Without Tier 2 (no API key), these would all be blocked via the "never fail open" fallback. However, **29 payloads containing SELECT keywords were classified as safe reads** — these are the true critical failures where UNION-based injections and `DECLARE @var SELECT` patterns pass as legitimate.

### Tier 1 — Filesystem Analyzer

| Metric | Score |
|--------|-------|
| Total attack payloads tested | 1811 |
| True Positives (correctly blocked) | 1060 |
| False Negatives (missed attacks) | 751 |
| — of which ALLOW (complete miss) | 751 |
| False Positives (safe inputs wrongly blocked) | 0 |
| Recall | 58.53% |
| Precision | 100.0% |

**Analysis:** The filesystem analyzer catches the basics (../  traversal, /etc/passwd, /proc/) but misses entire categories of sensitive paths. The biggest gap is **log file paths** (334 missed) — paths like `/apache/logs/access.log`, `/var/log/mysql/`, `/var/log/auth.log` that leak sensitive server information. It also misses **server config files** (php.ini, httpd.conf, my.cnf), **dotfiles** (.bash_history, .bashrc), and URL-encoded variants not covered by the regex patterns.

### Tier 1 — HTTP Analyzer

| Metric | Score |
|--------|-------|
| Total attack payloads tested | 0 |
| True Positives (correctly blocked) | 0 |
| False Negatives (missed attacks) | 0 |
| False Positives (safe inputs wrongly blocked) | 0 |
| Recall | N/A (no SSRF payloads available) |
| Precision | N/A |

**Analysis:** Both SSRF payload files (`SSRF-domain-bypass.txt`, `SSRF-target-IPs.txt`) returned HTTP 404 from SecLists — these files no longer exist in the repository. Only safe-input testing was possible: all 5 safe URLs correctly received ALLOW. The existing test suite covers basic SSRF vectors (metadata endpoints, localhost, private IPs) and those all pass.

### Tier 2 — Semantic Judge

**Skipped** — `OPENAI_API_KEY` environment variable not set.

---

## Critical Failures (Fix Immediately)

### SQL Analyzer — ALLOW verdicts on attack payloads (29 total)

These are real SQLi payloads that the analyzer classified as safe read operations. This is the worst class of failure — these bypass the firewall completely.

**1. `@var select @var as var into temp end --`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**2. `UNION ALL SELECT`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**3. `and 1 in (select var from temp)--`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**4. `declare @s varchar (200) select @s = 0x73656c6 ...`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**5. `\x27UNION SELECT`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**6. `declare @s varchar(200) select @s = 0x77616974 ...`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**7. `) union select * from information_schema.tables;`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**8. `union all select @@version--`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**9. `union select 1,load_file('/etc/passwd'),1,1,1;`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**10. `union select`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**11. `select * from information_schema.tables--`**
- Technique: Schema enumeration via information_schema
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**12. `declare @s varchar(22) select @s =`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**13. `declare @s varchar (8000) select @s = 0x73656c ...`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**14. `(select top 1`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**15. `select`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**16. `x' AND 1=(SELECT COUNT(*) FROM tabname); --`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**17. `declare @q nvarchar (200) select @q = 0x770061 ...`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**18. `declare @q nvarchar (4000) select @q =`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**19. `select name from syscolumns where id = (sele ...`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**20. `UNION SELECT`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**21. `or 1 in (select @@version)--`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**22. `union select * from users where login = char ...`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**23. `declare @q nvarchar (200) select @q = 0x770061006900740066006F0072002000640065006C00610079002000270030003A0030003A003100`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**24. `declare @s varchar(200) select @s = 0x77616974666F722064656C61792027303A303A31302700 exec(@s)`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**25. `declare @s varchar (200) select @s = 0x73656c65637420404076657273696f6e exec(@s)`**
- Technique: Variable declaration with embedded exec/waitfor
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**26. `' UNION SELECT`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**27. `' UNION ALL SELECT`**
- Technique: UNION-based data exfiltration
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**28. `' (select top 1`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

**29. `1;SELECT%20*`**
- Technique: SELECT-based injection fragment
- Analyzer verdict: ALLOW (reasoning: "Read-only SQL operations: ['SELECT']")
- Why missed: The AST parser found a SELECT statement and classified it as read-only, ignoring the injection context (UNION, DECLARE, variable assignment, or preceding fragment)
- File: `agentgate/lib/analyzers/sql.py` → `_classify_statement()` and `_ast_pass()`

### Filesystem Analyzer — ALLOW verdicts on attack payloads (751 total)

Below are representative examples from each miss category. Every payload listed is a real LFI/path-traversal vector from SecLists that received an ALLOW verdict.

**Pattern: Log file paths (apache, nginx, app logs)** (352 failures)
- `admin/access_log`
- `/apache2/logs/access_log`
- `/apache2/logs/access.log`
- Why missed: Log file paths are not in the sensitive files list and don't match system directory prefixes. The analyzer has no concept of 'server-sensitive paths' beyond its hardcoded lists.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Absolute paths to sensitive locations** (130 failures)
- `/admin/install.php`
- `/./././././././././././boot.ini`
- `/.\\./.\\./.\\./.\\./.\\./.\\./boot.ini`
- Why missed: These paths target sensitive locations not covered by the system directory or sensitive file lists.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Other** (90 failures)
- `web.config`
- `\web.config`
- `config.asp`
- Why missed: Paths fall outside the hardcoded detection lists.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Server config files (php.ini, httpd.conf, etc.)** (83 failures)
- `/bin/php.ini`
- `/opt/xampp/etc/php.ini`
- `/php4\php.ini`
- Why missed: Server config files (php.ini, httpd.conf, etc.) are not in the `_SENSITIVE_FILES` list.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Traversal variants not caught by regex** (26 failures)
- `..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini`
- `..2fetc2fpasswd`
- `..2f..2fetc2fpasswd`
- Why missed: Traversal variants using alternative encodings (`..%5c`, `..2f`) bypass the regex patterns.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Null byte injection** (23 failures)
- `..2fetc2fpasswd%00`
- `..2f..2fetc2fpasswd%00`
- `..2f..2f..2fetc2fpasswd%00`
- Why missed: Null byte injection (`%00`) is used to truncate file extensions. The analyzer has no null byte detection.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Absolute /etc/ paths not in sensitive list** (18 failures)
- `/usr/etc/pure-ftpd.conf`
- `/usr/local/etc/pure-ftpd.conf`
- `/usr/local/etc/pureftpd.pdb`
- Why missed: These paths target sensitive locations not covered by the system directory or sensitive file lists.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Windows paths** (10 failures)
- `c:\AppServ\MySQL`
- `C:/boot.ini`
- `C:\boot.ini`
- Why missed: Windows paths using C:\\ or mixed separators aren't fully matched by the Windows system directory checks.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Dotfiles (.bash_history, .bashrc, etc.)** (9 failures)
- `/.bash_history`
- `/.bash_profile`
- `/.bashrc`
- Why missed: Dotfiles like .bash_history, .bashrc contain secrets and command history but aren't in `_SENSITIVE_FILES`.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: Double-URL-encoded backslash traversal** (5 failures)
- `/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00`
- `%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%  25%5c..%25%5c..%00`
- `%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00`
- Why missed: URL-encoded variants using `%2f` (/) or `%25%5c` (double-encoded \\) bypass the traversal regex patterns which only check for `%2e` (.) encoding, not slash encoding.
- File: `agentgate/lib/analyzers/filesystem.py`

**Pattern: URL-encoded slash with traversal** (5 failures)
- `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
- `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow`
- `..%2F..%2F..%2F%2F..%2F..%2F%2Fvar%2Fnamed`
- Why missed: URL-encoded variants using `%2f` (/) or `%25%5c` (double-encoded \\) bypass the traversal regex patterns which only check for `%2e` (.) encoding, not slash encoding.
- File: `agentgate/lib/analyzers/filesystem.py`

---

## False Positives (Fix Before Production)

**No false positives detected.** All safe inputs across all three analyzers were correctly classified as ALLOW. This indicates good precision — the problem is recall, not over-triggering.

---

## Failure Pattern Analysis

### SQL Analyzer Patterns

#### [CRITICAL] DECLARE/variable injection classified as SELECT — 11 failures (verdict: allow)

Payloads:
- `@var select @var as var into temp end --`
- `declare @s varchar (200) select @s = 0x73656c6 ...`
- `declare @s varchar(200) select @s = 0x77616974 ...`
- `declare @s varchar(22) select @s =`
- `declare @s varchar (8000) select @s = 0x73656c ...`

Root cause: `_classify_statement()` in `sql.py` only looks at the primary SQL statement type. When it finds SELECT, it returns "safe" regardless of whether the SELECT is part of a UNION injection, a DECLARE block with exec, or an information_schema probe.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add UNION detection — if any statement contains UNION keyword followed by SELECT, escalate or block
2. Add DECLARE/exec pattern detection — DECLARE with SELECT that references @variables followed by EXEC should not be classified as a safe read
3. Add information_schema / system table detection — SELECT from information_schema, sys.tables, etc. should escalate
4. Add `load_file()`, `INTO OUTFILE`, `INTO DUMPFILE` detection

Estimated effort: **medium**

#### [CRITICAL] UNION SELECT classified as safe read — 10 failures (verdict: allow)

Payloads:
- `UNION ALL SELECT`
- `\x27UNION SELECT`
- `) union select * from information_schema.tables;`
- `union all select @@version--`
- `union select 1,load_file('/etc/passwd'),1,1,1;`

Root cause: `_classify_statement()` in `sql.py` only looks at the primary SQL statement type. When it finds SELECT, it returns "safe" regardless of whether the SELECT is part of a UNION injection, a DECLARE block with exec, or an information_schema probe.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add UNION detection — if any statement contains UNION keyword followed by SELECT, escalate or block
2. Add DECLARE/exec pattern detection — DECLARE with SELECT that references @variables followed by EXEC should not be classified as a safe read
3. Add information_schema / system table detection — SELECT from information_schema, sys.tables, etc. should escalate
4. Add `load_file()`, `INTO OUTFILE`, `INTO DUMPFILE` detection

Estimated effort: **medium**

#### [CRITICAL] Injection with SELECT keyword misclassified — 8 failures (verdict: allow)

Payloads:
- `and 1 in (select var from temp)--`
- `select * from information_schema.tables--`
- `(select top 1`
- `select`
- `x' AND 1=(SELECT COUNT(*) FROM tabname); --`

Root cause: `_classify_statement()` in `sql.py` only looks at the primary SQL statement type. When it finds SELECT, it returns "safe" regardless of whether the SELECT is part of a UNION injection, a DECLARE block with exec, or an information_schema probe.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add UNION detection — if any statement contains UNION keyword followed by SELECT, escalate or block
2. Add DECLARE/exec pattern detection — DECLARE with SELECT that references @variables followed by EXEC should not be classified as a safe read
3. Add information_schema / system table detection — SELECT from information_schema, sys.tables, etc. should escalate
4. Add `load_file()`, `INTO OUTFILE`, `INTO DUMPFILE` detection

Estimated effort: **medium**

#### [HIGH] Boolean-based tautology injection — 130 failures (verdict: escalate)

Payloads:
- `"hi"") or (""a""=""a"`
- `or 0=0 #`
- `) or ('a'='a`
- `"a"" or 3=3--"`
- `or 0=0 --`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] Other injection fragments — 109 failures (verdict: escalate)

Payloads:
- `)%20or%20('x'='x`
- `%20or%201=1`
- `(||6)`
- `0`
- `21 %`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] Time-based blind injection — 81 failures (verdict: escalate)

Payloads:
- `benchmark(10000000,MD5(1))#`
- `";waitfor delay '0:0:__TIME__'--`
- `1) or pg_sleep(__TIME__)--`
- `" or sleep(__TIME__)#`
- `pg_sleep(__TIME__)--`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] Stored procedure / exec injection — 16 failures (verdict: escalate)

Payloads:
- `; execute immediate 'sel' || 'ect us' || 'er'`
- `declare @q nvarchar (200) 0x730065006c00650063 ...`
- `; exec xp_regread`
- `exec xp`
- `; exec master..xp_cmdshell 'ping 172.10.1.255'--`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] Encoding/obfuscation-based injection — 8 failures (verdict: escalate)

Payloads:
- `||(elt(-3+5,bin(15),ord(10),hex(char(45))))`
- `1;(load_file(char(47,101,116,99,47,112,97,115, ...`
- `and 1=( if((load_file(char(110,46,101,120,11 ...`
- `0x770061006900740066006F0072002000640065006C00 ...`
- `0x77616974666F722064656C61792027303A303A313027 ...`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] SQL keyword fragments — 3 failures (verdict: escalate)

Payloads:
- `like`
- `asc`
- `desc`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] LDAP injection (non-SQL) — 3 failures (verdict: escalate)

Payloads:
- `*(|(objectclass=*))`
- `*|`
- `%2A%28%7C%28objectclass%3D%2A%29%29`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] Write operation injection — 2 failures (verdict: escalate)

Payloads:
- `update`
- `insert`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

#### [HIGH] UNION-based injection — 2 failures (verdict: escalate)

Payloads:
- `1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055`
- `1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055`

Root cause: The SQL analyzer is designed for complete SQL statements but SQLi payloads are injection fragments. `sqlparse` cannot determine a statement type for fragments like `' OR 1=1 --` or `benchmark(10000000,MD5(1))#`, so they all get ESCALATE. Without Tier 2, these are blocked by the "never fail open" fallback — but if Tier 2 is enabled, the LLM judge must correctly handle these fragments.

Fix: In `agentgate/lib/analyzers/sql.py`:
1. Add a fragment-detection pass before AST parsing — if the input looks like a SQL injection fragment (starts with `'`, `"`, `)`, contains `OR`/`AND` with comparison operators, contains `--`, `#`, or `/*` comment terminators), classify as BLOCK directly
2. Add time-based blind SQLi pattern detection (sleep, waitfor, benchmark, pg_sleep)
3. Add boolean-based blind detection (OR 1=1, OR 'a'='a patterns)

Estimated effort: **medium**

### Filesystem Analyzer Patterns

#### [HIGH] Log file paths (apache, nginx, app logs) — 352 failures

Examples:
- `admin/access_log`
- `/apache2/logs/access_log`
- `/apache2/logs/access.log`

Root cause: `_SENSITIVE_FILES` and `_SYSTEM_DIRS_UNIX` don't cover log directories (/var/log/, /apache/logs/, etc.) or web server log paths.

Fix: Add log path patterns to `_SENSITIVE_FILES` or create a new `_LOG_PATHS` list in `filesystem.py`. Include: access.log, error.log, auth.log, syslog, /var/log/, /apache/logs/, /nginx/logs/, and common web server log locations.

Estimated effort: **small**

#### [HIGH] Absolute paths to sensitive locations — 130 failures

Examples:
- `/admin/install.php`
- `/./././././././././././boot.ini`
- `/.\\./.\\./.\\./.\\./.\\./.\\./boot.ini`

Root cause: Many absolute paths targeting sensitive locations fall outside the hardcoded system directory and sensitive file lists.

Fix: Expand `_SYSTEM_DIRS_UNIX` and `_SENSITIVE_FILES` lists, and consider a more permissive approach: block or escalate ANY absolute path unless it's in an explicitly allowed set (allowlist approach vs. blocklist).

Estimated effort: **medium**

#### [HIGH] Other — 90 failures

Examples:
- `web.config`
- `\web.config`
- `config.asp`

Root cause: Paths fall outside the current detection scope.

Fix: Expand detection lists or implement URL-decoding as a preprocessing step.

Estimated effort: **small**

#### [HIGH] Server config files (php.ini, httpd.conf, etc.) — 83 failures

Examples:
- `/bin/php.ini`
- `/opt/xampp/etc/php.ini`
- `/php4\php.ini`

Root cause: Server configuration files are not in `_SENSITIVE_FILES`.

Fix: Add common config files to `_SENSITIVE_FILES`: php.ini, httpd.conf, my.cnf, my.ini, postgresql.conf, nginx.conf, wp-config.php, .htaccess, web.xml, application.yml/properties.

Estimated effort: **small**

#### [HIGH] Traversal variants not caught by regex — 26 failures

Examples:
- `..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini`
- `..2fetc2fpasswd`
- `..2f..2fetc2fpasswd`

Root cause: Paths fall outside the current detection scope.

Fix: Expand detection lists or implement URL-decoding as a preprocessing step.

Estimated effort: **small**

#### [HIGH] Null byte injection — 23 failures

Examples:
- `..2fetc2fpasswd%00`
- `..2f..2fetc2fpasswd%00`
- `..2f..2f..2fetc2fpasswd%00`

Root cause: No null byte (`%00`) detection. Null bytes can truncate file extensions in some server-side languages.

Fix: Add null byte detection regex to `_TRAVERSAL_PATTERNS`: `re.compile(r"%00")`. Also URL-decode before checking.

Estimated effort: **small**

#### [HIGH] Absolute /etc/ paths not in sensitive list — 18 failures

Examples:
- `/usr/etc/pure-ftpd.conf`
- `/usr/local/etc/pure-ftpd.conf`
- `/usr/local/etc/pureftpd.pdb`

Root cause: Many absolute paths targeting sensitive locations fall outside the hardcoded system directory and sensitive file lists.

Fix: Expand `_SYSTEM_DIRS_UNIX` and `_SENSITIVE_FILES` lists, and consider a more permissive approach: block or escalate ANY absolute path unless it's in an explicitly allowed set (allowlist approach vs. blocklist).

Estimated effort: **medium**

#### [HIGH] Windows paths — 10 failures

Examples:
- `c:\AppServ\MySQL`
- `C:/boot.ini`
- `C:\boot.ini`

Root cause: Windows path checks only cover a limited set of system directories. Paths like `C:\boot.ini` or mixed separator paths are not matched.

Fix: Expand Windows path detection, add `boot.ini`, `win.ini`, `system.ini` to sensitive files, and normalize backslash/forward-slash variants before checking.

Estimated effort: **small**

#### [HIGH] Dotfiles (.bash_history, .bashrc, etc.) — 9 failures

Examples:
- `/.bash_history`
- `/.bash_profile`
- `/.bashrc`

Root cause: Dotfiles like .bash_history and .bashrc are not in the sensitive files list.

Fix: Add common dotfiles to `_SENSITIVE_FILES`: .bash_history, .bash_profile, .bashrc, .zsh_history, .profile, .viminfo, .netrc, .pgpass, .mysql_history.

Estimated effort: **small**

#### [HIGH] Double-URL-encoded backslash traversal — 5 failures

Examples:
- `/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00`
- `%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%  25%5c..%25%5c..%00`
- `%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00`

Root cause: The traversal regex patterns only check for `%2e` (dot) URL encoding but not `%2f` (slash) or `%5c` (backslash) encoding. Double-encoded variants (`%25%5c`) are also missed.

Fix: In `filesystem.py`, add URL-decoding before analysis: run `urllib.parse.unquote()` (and double-unquote for `%25` patterns) on the path before running all checks. This single change would catch all URL-encoded traversal variants.

Estimated effort: **small**

#### [HIGH] URL-encoded slash with traversal — 5 failures

Examples:
- `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`
- `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow`
- `..%2F..%2F..%2F%2F..%2F..%2F%2Fvar%2Fnamed`

Root cause: The traversal regex patterns only check for `%2e` (dot) URL encoding but not `%2f` (slash) or `%5c` (backslash) encoding. Double-encoded variants (`%25%5c`) are also missed.

Fix: In `filesystem.py`, add URL-decoding before analysis: run `urllib.parse.unquote()` (and double-unquote for `%25` patterns) on the path before running all checks. This single change would catch all URL-encoded traversal variants.

Estimated effort: **small**

---

## Tier 2 Analysis

**Skipped** — `OPENAI_API_KEY` environment variable was not set. Phase 3 (Tier 2 semantic audit with GPT-4o adversarial prompts) could not be executed. To run this phase:

```
export OPENAI_API_KEY=sk-...
python redteam/run_audit.py
```

**Note on Tier 2 dependency:** The SQL analyzer's heavy reliance on ESCALATE means Tier 2 is the *de facto* security boundary for most SQL injection attacks. If Tier 2 is unavailable, the "never fail open" fallback blocks everything that escalates — which is safe but creates a very high false-positive rate for legitimate SQL operations that happen to be unparseable fragments. If Tier 2 IS available, its accuracy against adversarial SQL fragments is untested and represents a significant unknown risk.

---

## Integration Results

| PASS | guard_blocks_dangerous | None |
| PASS | langchain_patch | None |
| PASS | openai_patch | None |
| PASS | async_guard_blocks | None |
| PASS | scope_blocks_outside | None |

**All 5/5 integration tests passed.** `protect_all()` correctly patches OpenAI and LangChain interceptors, the `@guard` decorator blocks dangerous calls in both sync and async modes, and the `scope()` context manager correctly restricts operations to declared resources.

---

## Performance

| Metric | Value |
|--------|-------|
| Total calls | 1000 |
| Allowed | 700 |
| Blocked | 300 |
| p50 latency | 0.0243ms |
| p95 latency | 0.2586ms |
| p99 latency | 0.4048ms |
| Mean latency | 0.086ms |
| Min latency | 0.0058ms |
| Max latency | 0.7127ms |
| p99 target (≤5ms) | **PASS** |

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
