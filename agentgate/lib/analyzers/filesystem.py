"""Filesystem path analysis for path traversal, system directory access, and symlink escapes."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import ClassVar

from agentgate.lib.models import Severity, VerdictType

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.$"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e[/\\%]", re.IGNORECASE),
    re.compile(r"\.%2e[/\\%]", re.IGNORECASE),
    re.compile(r"%2e\.[/\\%]", re.IGNORECASE),
    re.compile(r"%252e%252e", re.IGNORECASE),
]

_SYSTEM_DIRS_UNIX: list[str] = [
    "/etc/", "/proc/", "/sys/", "/dev/", "/boot/",
    "/root/", "/var/log/", "/var/run/",
    "/usr/sbin/", "/sbin/",
]

_SYSTEM_DIRS_WINDOWS: list[str] = [
    "C:\\Windows\\", "C:\\System32\\", "C:\\Program Files\\",
    "\\\\", "C:\\ProgramData\\",
]

_SENSITIVE_FILES: list[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    ".env", ".ssh/", "id_rsa", "id_ed25519",
    ".aws/credentials", ".git/config",
    ".kube/config", ".docker/config.json",
]


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


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
        """Analyze a filesystem path for security threats.

        Args:
            path: The file path to evaluate.
            operation: The intended operation (read, write, delete, execute).

        Returns:
            FilesystemAnalysisResult with verdict and detected threats.
        """
        if not path or not path.strip():
            return FilesystemAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="Empty path",
                threats=[],
            )

        threats: list[str] = []
        max_severity = Severity.LOW

        traversal = self._check_traversal(path)
        if traversal:
            threats.append(traversal)
            max_severity = _max_sev(max_severity, Severity.CRITICAL)

        normalized = self._normalize_path(path)

        system_dir = self._check_system_dirs(normalized)
        if system_dir:
            threats.append(system_dir)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        sensitive = self._check_sensitive_files(normalized)
        if sensitive:
            threats.append(sensitive)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        symlink = self._check_symlink_escape(path)
        if symlink:
            threats.append(symlink)
            max_severity = _max_sev(max_severity, Severity.MEDIUM)

        if operation in ("delete", "execute") and not threats:
            max_severity = Severity.MEDIUM
            threats.append(f"Potentially dangerous operation: {operation}")

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

    def _normalize_path(self, path: str) -> str:
        """Normalize a path for analysis, resolving traversals."""
        try:
            return os.path.normpath(path)
        except (ValueError, OSError):
            return path

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

        for sys_dir in _SYSTEM_DIRS_WINDOWS:
            normalized = sys_dir.lower().replace("\\", "/")
            if path_lower.startswith(normalized):
                return f"System directory access: {sys_dir}"

        return None

    def _check_sensitive_files(self, path: str) -> str | None:
        """Check if the path targets known sensitive files."""
        path_lower = path.lower().replace("\\", "/")
        for sensitive in _SENSITIVE_FILES:
            if sensitive in path_lower:
                return f"Sensitive file access: {sensitive}"
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
