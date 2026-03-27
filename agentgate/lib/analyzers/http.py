"""HTTP request analysis for SSRF (Server-Side Request Forgery) detection.

Checks for internal IPs, cloud metadata endpoints, localhost variants, and IPv6 loopback.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlparse

from agentgate.lib.models import Severity, VerdictType


_METADATA_ENDPOINTS: list[str] = [
    "169.254.169.254",                  # AWS / GCP / Azure metadata
    "metadata.google.internal",         # GCP
    "metadata.goog",                    # GCP alt
    "100.100.100.200",                  # Alibaba Cloud
    "fd00:ec2::254",                    # AWS IPv6 metadata
]

_LOCALHOST_VARIANTS: list[re.Pattern[str]] = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^\[?::1\]?$"),
    re.compile(r"^\[?0:0:0:0:0:0:0:1\]?$"),
    re.compile(r"^0x7f", re.IGNORECASE),      # hex 127.x
    re.compile(r"^2130706433$"),               # decimal 127.0.0.1
    re.compile(r"^017700000001$"),             # octal 127.0.0.1
]

_PRIVATE_RANGES: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",     # IPv6 ULA
    "fe80::/10",    # IPv6 link-local
]


@dataclass
class HTTPAnalysisResult:
    """Outcome of analyzing an HTTP request target."""

    verdict: VerdictType
    severity: Severity
    reasoning: str
    threats: list[str]

    @property
    def is_ssrf(self) -> bool:
        return self.verdict == VerdictType.BLOCK


class HTTPAnalyzer:
    """Detects SSRF attacks targeting internal infrastructure and cloud metadata."""

    METADATA_ENDPOINTS: ClassVar[list[str]] = _METADATA_ENDPOINTS

    def analyze(self, url: str) -> HTTPAnalysisResult:
        """Analyze a URL for SSRF threats.

        Args:
            url: The target URL to evaluate.

        Returns:
            HTTPAnalysisResult with verdict and detected threats.
        """
        if not url or not url.strip():
            return HTTPAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="Empty URL",
                threats=[],
            )

        threats: list[str] = []
        max_severity = Severity.LOW

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            return HTTPAnalysisResult(
                verdict=VerdictType.ESCALATE,
                severity=Severity.MEDIUM,
                reasoning="URL could not be parsed — escalating to Tier 2",
                threats=["Unparseable URL"],
            )

        if not hostname:
            return HTTPAnalysisResult(
                verdict=VerdictType.ESCALATE,
                severity=Severity.MEDIUM,
                reasoning="No hostname in URL",
                threats=["Missing hostname"],
            )

        metadata = self._check_metadata_endpoint(hostname)
        if metadata:
            threats.append(metadata)
            max_severity = Severity.CRITICAL

        localhost = self._check_localhost(hostname)
        if localhost:
            threats.append(localhost)
            if max_severity != Severity.CRITICAL:
                max_severity = Severity.HIGH

        private_ip = self._check_private_ip(hostname)
        if private_ip:
            threats.append(private_ip)
            if max_severity == Severity.LOW:
                max_severity = Severity.HIGH

        scheme = self._check_dangerous_scheme(parsed.scheme)
        if scheme:
            threats.append(scheme)
            if max_severity == Severity.LOW:
                max_severity = Severity.HIGH

        if not threats:
            return HTTPAnalysisResult(
                verdict=VerdictType.ALLOW,
                severity=Severity.LOW,
                reasoning="URL appears safe",
                threats=[],
            )

        return HTTPAnalysisResult(
            verdict=VerdictType.BLOCK,
            severity=max_severity,
            reasoning=f"SSRF threats detected: {'; '.join(threats)}",
            threats=threats,
        )

    def _check_metadata_endpoint(self, hostname: str) -> str | None:
        """Check for cloud metadata service endpoints."""
        hostname_lower = hostname.lower().strip("[]")
        for endpoint in _METADATA_ENDPOINTS:
            if hostname_lower == endpoint.lower():
                return f"Cloud metadata endpoint: {endpoint}"
        return None

    def _check_localhost(self, hostname: str) -> str | None:
        """Check for localhost variants including hex and decimal encodings."""
        for pattern in _LOCALHOST_VARIANTS:
            if pattern.match(hostname):
                return f"Localhost variant detected: {hostname}"
        return None

    def _check_private_ip(self, hostname: str) -> str | None:
        """Check if the hostname resolves to a private/internal IP range."""
        try:
            clean = hostname.strip("[]")
            addr = ipaddress.ip_address(clean)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return f"Private/internal IP: {hostname}"
            for cidr in _PRIVATE_RANGES:
                if addr in ipaddress.ip_network(cidr):
                    return f"IP in private range {cidr}: {hostname}"
        except ValueError:
            pass
        return None

    def _check_dangerous_scheme(self, scheme: str) -> str | None:
        """Block non-HTTP(S) schemes that could be used for SSRF."""
        if scheme and scheme.lower() not in ("http", "https", ""):
            return f"Dangerous URL scheme: {scheme}"
        return None
