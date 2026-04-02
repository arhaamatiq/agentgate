"""Filesystem path analysis for path traversal, system directory access, and symlink escapes.

Multi-layer decode pipeline:
  1. Double URL-decode at the byte level (handles %25XX double-encoding)
  2. Overlong UTF-8 replacement (\\xc0\\xae → . , \\xc0\\xaf → /)
  3. Unicode NFKC normalization (fullwidth → ASCII: ／ → /, ‥ → ..)
  4. Null byte stripping

Detection layers:
  - Path traversal (regex + normalization)
  - System directory matching
  - Sensitive file substring matching
  - Pattern-based extension/directory matching (with /app/ exemption)
  - Bare sensitive basename matching
  - Base64-encoded path decoding
"""

from __future__ import annotations

import base64
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import unquote_to_bytes

from agentgate.lib.models import Severity, VerdictType


def _raw_percent_decode(data: bytes) -> bytes:
    """Percent-decode raw bytes without UTF-8 interpretation.

    Unlike ``unquote_to_bytes(data.decode('latin-1'))``, this preserves
    overlong UTF-8 byte sequences intact so they can be matched and replaced.
    """
    text = data.decode("latin-1")
    out: list[bytes] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "%" and i + 2 < n:
            pair = text[i + 1 : i + 3]
            try:
                out.append(bytes([int(pair, 16)]))
                i += 3
                continue
            except ValueError:
                pass
        out.append(ch.encode("latin-1"))
        i += 1
    return b"".join(out)


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


# ---------------------------------------------------------------------------
# Overlong UTF-8 sequences → intended ASCII characters
# ---------------------------------------------------------------------------
_OVERLONG_UTF8: list[tuple[bytes, bytes]] = [
    (b"\xc0\xae", b"."),
    (b"\xc0\xaf", b"/"),
    (b"\xc1\x9c", b"\\"),
    (b"\xc0\x2e", b"."),
    (b"\xe0\x80\xae", b"."),
    (b"\xe0\x80\xaf", b"/"),
    (b"\xf0\x80\x80\xae", b"."),
    (b"\xf0\x80\x80\xaf", b"/"),
]

# ---------------------------------------------------------------------------
# Traversal patterns
# ---------------------------------------------------------------------------
_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.$"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e[/\\%]", re.IGNORECASE),
    re.compile(r"\.%2e[/\\%]", re.IGNORECASE),
    re.compile(r"%2e\.[/\\%]", re.IGNORECASE),
    re.compile(r"%252e%252e", re.IGNORECASE),
    re.compile(r"\.\.2[fF]"),
    re.compile(r"2[fF]\.\."),
    re.compile(r"\.\.%5[cC]", re.IGNORECASE),
    re.compile(r"%5[cC]\.\.", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# System directories
# ---------------------------------------------------------------------------
_SYSTEM_DIRS_UNIX: list[str] = [
    "/etc/", "/proc/", "/sys/", "/dev/", "/boot/",
    "/root/", "/var/log/", "/var/run/", "/var/www/",
    "/usr/sbin/", "/sbin/",
    "/usr/local/", "/usr/lib/", "/usr/etc/",
    "/usr/ports/", "/usr/pkgsrc/",
    "/apache/", "/apache2/",
    "/nginx/",
    "/srv/www/", "/srv/http/",
    "/opt/lampp/", "/opt/xampp/", "/opt/bitnami/",
    "/var/log",
    "/private/etc/",
    "/postgresql/",
]

_SYSTEM_DIRS_WINDOWS: list[str] = [
    "c:/windows/", "c:/system32/", "c:/program files/",
    "c:/program files (x86)/", "c:/programdata/",
    "c:/inetpub/", "c:/xampp/", "c:/wamp/", "c:/wamp64/",
    "c:/appserv/",
    "d:/program files/", "d:/appserv/",
]

_WINDOWS_DRIVE_RE = re.compile(r"[a-zA-Z]:[/\\]|^[a-zA-Z]:[a-zA-Z]")

# ---------------------------------------------------------------------------
# Sensitive files — substring match against the decoded, normalized path
# ---------------------------------------------------------------------------
_SENSITIVE_FILES: list[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
    "/etc/master.passwd", "/etc/security/passwd", "/etc/gshadow",
    ".env", ".ssh/", "id_rsa", "id_ed25519", "id_dsa",
    ".aws/credentials", ".git/config", ".git/HEAD",
    ".kube/config", ".docker/config.json",
    "authorized_keys", "known_hosts",

    "access.log", "access_log", "accesslog",
    "error.log", "error_log", "errorlog",
    "auth.log", "syslog", "messages",
    "debug.log", "mail.log", "daemon.log",
    "pure-ftpd.log", "pureftpd.log",
    "pgadmin.log", "mysql.log", "postgresql.log",
    "catalina.out",

    "php.ini", "httpd.conf", "apache2.conf", "nginx.conf",
    "my.cnf", "my.ini", "postgresql.conf", "pg_hba.conf",
    ".htaccess", ".htpasswd",
    "lighttpd.conf", "squid.conf",
    "proftpd.conf", "vsftpd.conf", "pure-ftpd.conf", "pureftpd.conf",
    "smb.conf", "sshd_config", "ssh_config",
    "resolv.conf", "fstab", "crontab",
    "named.conf",
    "pureftpd.pdb", "pureftpd.passwd",

    ".bash_history", ".bashrc", ".bash_profile", ".bash_logout",
    ".zsh_history", ".zshrc", ".zprofile", ".zlogin", ".zlogout",
    ".profile", ".netrc", ".wgetrc", ".curlrc",
    ".pgpass", ".mysql_history", ".viminfo", ".vimrc",
    ".cshrc", ".tcshrc", ".logout", ".login", ".forward",
    ".rhosts", ".shosts", ".exrc",

    "wp-config.php", "configuration.php", "config.php",
    "config.inc.php", "LocalSettings.php", "local_settings.py",
    "database.yml", "database.php",
    "settings.php", "parameters.yml", "parameters.ini",
    "web.config", "machine.config", "app.config",
    "connectionstrings.config",

    "global.asa", "global.asax",

    "boot.ini", "win.ini", "system.ini",
    "autoexec.bat", "config.sys",
    "sam", "ntuser.dat",

    "web.xml", "server.xml", "context.xml",
    ".DS_Store",

    "config.asp", "config.aspx", "config.js",
    "database.asp", "database.aspx", "database.js",
    "install.php", "setup.php", "phpinfo.php",

    "master.passwd", "pass.dat", "passwd.dat",
    "mkuser.default",
]

# ---------------------------------------------------------------------------
# Sensitive basenames — matched against the filename component only
# Catches bare filenames with no path prefix (passwd, .pass, db.php, etc.)
# ---------------------------------------------------------------------------
_SENSITIVE_BASENAMES: frozenset[str] = frozenset({
    "passwd", "shadow", "master.passwd", "group",
    ".passwd", ".pass", ".passw", ".password",
    "pass.dat", "passwd.dat", "password.dat",
    "db.php", "data.php", "users.db", "users.db.php",
    "mkuser.default", "htpasswd", ".htpasswd",
    ".pgpass", ".my.cnf",
})

_SENSITIVE_BASENAME_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.(?:key|pem|p12|pfx|jks|keystore)$", re.IGNORECASE), "Cryptographic key file"),
    (re.compile(r"\.(?:crt|cer|der)$", re.IGNORECASE), "Certificate file"),
    (re.compile(
        r"(?:credential|secret|private[_-]?key|signing[_-]?key|"
        r"api[_-]?key|master[_-]?key|keystore)",
        re.IGNORECASE,
    ), "Credential/secret file"),
]

# ---------------------------------------------------------------------------
# Pattern-based sensitive file detection (regex on the normalized path).
# These are SKIPPED for application paths (/app/, app/, ./app/) to avoid
# false positives on application-owned files like /app/logs/app.log.
# ---------------------------------------------------------------------------
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.conf$", re.IGNORECASE), "Configuration file"),
    (re.compile(r"\.cfg$", re.IGNORECASE), "Configuration file"),
    (re.compile(r"(?:^|[/\\])config\.\w+$", re.IGNORECASE), "Config file (config.*)"),
    (re.compile(r"(?:^|[/\\])database\.\w+$", re.IGNORECASE), "Database config (database.*)"),
    (re.compile(r"(?:^|[/\\])global\.asa[x]?$", re.IGNORECASE), "ASP global config"),
    (re.compile(r"(?:^|[/\\])(?:install|setup)\.\w+$", re.IGNORECASE), "Admin/install script"),
    (re.compile(r"(?:^|[/\\])phpinfo\.\w+$", re.IGNORECASE), "PHP info exposure"),
    (re.compile(r"(?:^|/)backups?(?:/|$)", re.IGNORECASE), "Backup directory"),
]

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{12,}={0,3}$")


@dataclass
class FilesystemAnalysisResult:
    """Outcome of analyzing a filesystem path."""

    verdict: VerdictType
    severity: Severity
    reasoning: str
    threats: list[str]

    @property
    def is_dangerous(self) -> bool:
        return self.verdict == VerdictType.BLOCK


class FilesystemAnalyzer:
    """Detects path traversal attacks, system directory access, and symlink escapes."""

    SYSTEM_DIRS_UNIX: ClassVar[list[str]] = _SYSTEM_DIRS_UNIX
    SYSTEM_DIRS_WINDOWS: ClassVar[list[str]] = _SYSTEM_DIRS_WINDOWS

    def analyze(self, path: str, operation: str = "read") -> FilesystemAnalysisResult:
        """Analyze a filesystem path for security threats."""
        if not path or not path.strip():
            return FilesystemAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="Empty path",
                threats=[],
            )

        has_null_bytes = "\x00" in path or "%00" in path.lower()
        decoded = self._decode_path(path)

        threats: list[str] = []
        max_severity = Severity.LOW

        if has_null_bytes:
            threats.append("Null byte injection detected")
            max_severity = _max_sev(max_severity, Severity.HIGH)

        traversal = self._check_traversal(decoded)
        if not traversal:
            traversal = self._check_traversal(path)
        if traversal:
            threats.append(traversal)
            max_severity = _max_sev(max_severity, Severity.CRITICAL)

        normalized = self._normalize_path(decoded)

        system_dir = self._check_system_dirs(normalized)
        if system_dir:
            threats.append(system_dir)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        windows = self._check_windows_path(decoded)
        if windows:
            threats.append(windows)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        sensitive = self._check_sensitive_files(normalized)
        if sensitive:
            threats.append(sensitive)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        basename_threat = self._check_sensitive_basenames(normalized)
        if basename_threat:
            threats.append(basename_threat)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        if not self._is_app_path(normalized):
            pattern = self._check_sensitive_patterns(normalized)
            if pattern:
                threats.append(pattern)
                max_severity = _max_sev(max_severity, Severity.HIGH)

        b64 = self._check_base64(path)
        if b64:
            threats.append(b64)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        symlink = self._check_symlink_escape(path)
        if symlink:
            threats.append(symlink)
            max_severity = _max_sev(max_severity, Severity.MEDIUM)

        if decoded.strip("/") == "" and decoded.strip():
            threats.append("Root filesystem access")
            max_severity = _max_sev(max_severity, Severity.HIGH)

        if operation == "delete":
            if any(c in decoded for c in ("*", "?")):
                threats.append("Wildcard deletion pattern — unknown blast radius")
                max_severity = _max_sev(max_severity, Severity.HIGH)
            elif decoded.strip("/") and not os.path.splitext(os.path.basename(decoded))[1]:
                threats.append(
                    "Deletion target has no file extension — possible directory deletion"
                )
                max_severity = _max_sev(max_severity, Severity.HIGH)
            elif not threats:
                max_severity = Severity.MEDIUM
                threats.append("Potentially dangerous operation: delete")
        elif operation == "execute" and not threats:
            max_severity = Severity.MEDIUM
            threats.append("Potentially dangerous operation: execute")

        if not threats:
            return FilesystemAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="Path appears safe",
                threats=[],
            )

        should_block = max_severity in (Severity.CRITICAL, Severity.HIGH)
        return FilesystemAnalysisResult(
            verdict=VerdictType.BLOCK if should_block else VerdictType.ESCALATE,
            severity=max_severity,
            reasoning=f"Filesystem threats detected: {'; '.join(threats)}",
            threats=threats,
        )

    # ------------------------------------------------------------------
    # Preprocessing
    # ------------------------------------------------------------------

    def _decode_path(self, path: str) -> str:
        """Multi-layer decode: URL bytes → overlong UTF-8 → NFKC → strip nulls."""
        raw = unquote_to_bytes(path)
        raw = _raw_percent_decode(raw)

        for old, new in _OVERLONG_UTF8:
            raw = raw.replace(old, new)
        raw = raw.replace(b"\x00", b"")

        decoded = raw.decode("utf-8", errors="replace")
        decoded = unicodedata.normalize("NFKC", decoded)
        decoded = decoded.replace("\ufffd", "").replace("\x00", "")
        return decoded

    def _normalize_path(self, path: str) -> str:
        """Normalize a path for analysis, resolving traversals."""
        try:
            return os.path.normpath(path)
        except (ValueError, OSError):
            return path

    @staticmethod
    def _is_app_path(path: str) -> bool:
        """True if the path is in application space (exempt from broad patterns)."""
        lower = path.lower()
        return lower.startswith("/app/") or lower.startswith("app/") or lower.startswith("./app/")

    # ------------------------------------------------------------------
    # Threat checks
    # ------------------------------------------------------------------

    def _check_traversal(self, path: str) -> str | None:
        """Detect directory traversal attempts including URL-encoded variants."""
        for pattern in _TRAVERSAL_PATTERNS:
            if pattern.search(path):
                return f"Path traversal detected: {pattern.pattern}"
        try:
            normalized = os.path.normpath(path)
            if normalized != path and ".." in path:
                return f"Path normalization reveals traversal: {path} -> {normalized}"
        except (ValueError, OSError):
            pass
        return None

    def _check_system_dirs(self, path: str) -> str | None:
        """Check if the path targets sensitive system directories."""
        path_lower = path.lower().replace("\\", "/")
        if not path_lower.startswith("/"):
            path_lower = "/" + path_lower

        for sys_dir in _SYSTEM_DIRS_UNIX:
            if path_lower.startswith(sys_dir) or path_lower == sys_dir.rstrip("/"):
                return f"System directory access: {sys_dir}"

        check_paths = [path_lower]
        if path_lower.startswith("/"):
            check_paths.append(path_lower[1:])

        for check in check_paths:
            for sys_dir in _SYSTEM_DIRS_WINDOWS:
                if check.startswith(sys_dir):
                    return f"Windows system directory: {sys_dir}"

        return None

    def _check_windows_path(self, path: str) -> str | None:
        """Detect any Windows drive-letter path (C:\\, D:/, c:WINDOWS)."""
        if _WINDOWS_DRIVE_RE.search(path):
            return "Windows drive letter path detected"
        return None

    def _check_sensitive_files(self, path: str) -> str | None:
        """Check if the path targets known sensitive files."""
        path_lower = path.lower().replace("\\", "/")
        for sensitive in _SENSITIVE_FILES:
            if sensitive in path_lower:
                return f"Sensitive file access: {sensitive}"
        return None

    def _check_sensitive_basenames(self, path: str) -> str | None:
        """Check the filename component against known sensitive basenames."""
        basename = os.path.basename(path.replace("\\", "/")).lower()
        if not basename:
            return None
        if basename in _SENSITIVE_BASENAMES:
            return f"Sensitive basename: {basename}"
        for pattern, description in _SENSITIVE_BASENAME_PATTERNS:
            if pattern.search(basename):
                return f"Sensitive basename pattern: {description}"
        return None

    def _check_sensitive_patterns(self, path: str) -> str | None:
        """Pattern-based detection for file extensions and directory contexts."""
        path_normalized = path.replace("\\", "/")
        for pattern, description in _SENSITIVE_PATH_PATTERNS:
            if pattern.search(path_normalized):
                return f"Sensitive pattern match: {description}"
        return None

    def _check_base64(self, path: str) -> str | None:
        """Detect base64-encoded paths that decode to sensitive targets."""
        stripped = path.strip()
        if not _BASE64_RE.match(stripped):
            return None
        try:
            decoded = base64.b64decode(stripped).decode("utf-8", errors="strict")
        except Exception:
            return None
        if not any(c in decoded for c in ("/", "\\")):
            return None
        normalized = self._normalize_path(decoded)
        if self._check_system_dirs(normalized):
            return f"Base64-encoded path to system directory: {decoded}"
        if self._check_sensitive_files(normalized):
            return f"Base64-encoded sensitive file: {decoded}"
        if self._check_traversal(decoded):
            return f"Base64-encoded path traversal: {decoded}"
        return None

    def _check_symlink_escape(self, path: str) -> str | None:
        """Detect potential symlink-based escapes (best-effort, path may not exist)."""
        try:
            if os.path.islink(path):
                target = os.path.realpath(path)
                if target != os.path.abspath(path):
                    return f"Symlink escape: {path} -> {target}"
        except (OSError, ValueError):
            pass
        return None
