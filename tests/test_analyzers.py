"""Tests for the Tier 1 static analyzers — SQL, filesystem, HTTP."""


from agentgate.analyzers.sql import SQLAnalyzer
from agentgate.analyzers.filesystem import FilesystemAnalyzer
from agentgate.analyzers.http import HTTPAnalyzer
from agentgate.models import VerdictType, Severity


class TestSQLAnalyzer:
    """Test the two-pass SQL analyzer."""

    def setup_method(self) -> None:
        self.analyzer = SQLAnalyzer()

    def test_select_is_safe(self) -> None:
        result = self.analyzer.analyze("SELECT * FROM users WHERE id = 1")
        assert result.verdict == VerdictType.ALLOW
        assert result.severity == Severity.LOW

    def test_drop_table_is_blocked(self) -> None:
        result = self.analyzer.analyze("DROP TABLE users")
        assert result.verdict == VerdictType.BLOCK
        assert result.severity == Severity.CRITICAL

    def test_delete_from_is_blocked(self) -> None:
        result = self.analyzer.analyze("DELETE FROM users WHERE 1=1")
        assert result.verdict == VerdictType.BLOCK
        assert result.severity == Severity.HIGH

    def test_truncate_is_blocked(self) -> None:
        result = self.analyzer.analyze("TRUNCATE TABLE sessions")
        assert result.verdict == VerdictType.BLOCK
        assert result.severity == Severity.CRITICAL

    def test_alter_table_is_blocked(self) -> None:
        result = self.analyzer.analyze("ALTER TABLE users DROP COLUMN email")
        assert result.verdict == VerdictType.BLOCK

    def test_comment_obfuscation_caught(self) -> None:
        """SQL with comments trying to hide destructive intent."""
        result = self.analyzer.analyze("DR/**/OP TABLE users")
        assert result.verdict in (VerdictType.BLOCK, VerdictType.ESCALATE)

    def test_case_insensitive_detection(self) -> None:
        result = self.analyzer.analyze("drop table users")
        assert result.verdict == VerdictType.BLOCK

    def test_multi_statement_with_drop(self) -> None:
        sql = "SELECT 1; DROP TABLE users;"
        result = self.analyzer.analyze(sql)
        assert result.verdict == VerdictType.BLOCK

    def test_empty_sql_is_safe(self) -> None:
        result = self.analyzer.analyze("")
        assert result.verdict == VerdictType.ALLOW

    def test_insert_escalates_or_allows(self) -> None:
        result = self.analyzer.analyze("INSERT INTO logs (msg) VALUES ('hello')")
        assert result.verdict in (VerdictType.ESCALATE, VerdictType.ALLOW)

    def test_grant_is_blocked(self) -> None:
        result = self.analyzer.analyze("GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'")
        assert result.verdict == VerdictType.BLOCK

    def test_explain_is_safe(self) -> None:
        result = self.analyzer.analyze("EXPLAIN SELECT * FROM users")
        assert result.verdict == VerdictType.ALLOW


class TestFilesystemAnalyzer:
    """Test path traversal and system directory detection."""

    def setup_method(self) -> None:
        self.analyzer = FilesystemAnalyzer()

    def test_safe_path(self) -> None:
        result = self.analyzer.analyze("./reports/sales.csv")
        assert result.verdict == VerdictType.ALLOW

    def test_traversal_dotdot(self) -> None:
        result = self.analyzer.analyze("../../etc/passwd")
        assert result.verdict == VerdictType.BLOCK
        assert result.severity == Severity.CRITICAL

    def test_traversal_url_encoded(self) -> None:
        result = self.analyzer.analyze("%2e%2e/%2e%2e/etc/passwd")
        assert result.verdict == VerdictType.BLOCK

    def test_system_dir_etc(self) -> None:
        result = self.analyzer.analyze("/etc/shadow")
        assert result.verdict == VerdictType.BLOCK

    def test_system_dir_proc(self) -> None:
        result = self.analyzer.analyze("/proc/self/environ")
        assert result.verdict == VerdictType.BLOCK

    def test_sensitive_env_file(self) -> None:
        result = self.analyzer.analyze("/app/.env")
        assert result.verdict == VerdictType.BLOCK

    def test_sensitive_ssh_key(self) -> None:
        result = self.analyzer.analyze("/home/user/.ssh/id_rsa")
        assert result.verdict == VerdictType.BLOCK

    def test_aws_credentials(self) -> None:
        result = self.analyzer.analyze("/home/user/.aws/credentials")
        assert result.verdict == VerdictType.BLOCK

    def test_empty_path_safe(self) -> None:
        result = self.analyzer.analyze("")
        assert result.verdict == VerdictType.ALLOW

    def test_delete_operation_escalates(self) -> None:
        result = self.analyzer.analyze("safe_file.txt", operation="delete")
        assert result.verdict in (VerdictType.ESCALATE, VerdictType.BLOCK)


class TestHTTPAnalyzer:
    """Test SSRF detection."""

    def setup_method(self) -> None:
        self.analyzer = HTTPAnalyzer()

    def test_public_url_safe(self) -> None:
        result = self.analyzer.analyze("https://api.example.com/data")
        assert result.verdict == VerdictType.ALLOW

    def test_aws_metadata_blocked(self) -> None:
        result = self.analyzer.analyze("http://169.254.169.254/latest/meta-data/")
        assert result.verdict == VerdictType.BLOCK
        assert result.severity == Severity.CRITICAL

    def test_gcp_metadata_blocked(self) -> None:
        result = self.analyzer.analyze("http://metadata.google.internal/computeMetadata/v1/")
        assert result.verdict == VerdictType.BLOCK

    def test_localhost_blocked(self) -> None:
        result = self.analyzer.analyze("http://localhost:8080/admin")
        assert result.verdict == VerdictType.BLOCK

    def test_localhost_127(self) -> None:
        result = self.analyzer.analyze("http://127.0.0.1:3000/")
        assert result.verdict == VerdictType.BLOCK

    def test_ipv6_loopback_blocked(self) -> None:
        result = self.analyzer.analyze("http://[::1]:8080/")
        assert result.verdict == VerdictType.BLOCK

    def test_private_ip_10_blocked(self) -> None:
        result = self.analyzer.analyze("http://10.0.0.1:9200/")
        assert result.verdict == VerdictType.BLOCK

    def test_private_ip_192_blocked(self) -> None:
        result = self.analyzer.analyze("http://192.168.1.1/admin")
        assert result.verdict == VerdictType.BLOCK

    def test_ftp_scheme_blocked(self) -> None:
        result = self.analyzer.analyze("ftp://internal-server/data")
        assert result.verdict == VerdictType.BLOCK

    def test_empty_url_safe(self) -> None:
        result = self.analyzer.analyze("")
        assert result.verdict == VerdictType.ALLOW

    def test_zero_ip_blocked(self) -> None:
        result = self.analyzer.analyze("http://0.0.0.0:8080/")
        assert result.verdict == VerdictType.BLOCK
