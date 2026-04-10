"""HTTP request analysis for SSRF (Server-Side Request Forgery) detection.

Comprehensive coverage:
  - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle, k8s)
  - Cloud hostname aliases (instance-data, metadata, ip6-localhost)
  - IP obfuscation: decimal, octal (0177/o177/0o177), hex, short-form, mixed
  - Short-form IP expansion: 127.1 → 127.0.0.1 (POSIX inet_aton rules)
  - IPv4-mapped IPv6 extraction: ::ffff:a9fe:a9fe → 169.254.169.254
  - AWS EC2 IPv6 metadata range: fd00:ec2::/32
  - Dangerous protocol handlers: file://, gopher://, dict://, ldap://, etc.
  - DNS rebinding domains: nip.io, xip.io, sslip.io, r3dir.me, etc.
  - URL parser confusion: credential stuffing (@), backslash, multiple @
  - Template variable detection: ${VAR}, $VAR
  - Unicode NFKC hostname normalization (enclosed alphanumerics → ASCII)
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlparse

from agentgate.models import Severity, VerdictType

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


# ---------------------------------------------------------------------------
# Cloud metadata endpoints — hostname string matches
# ---------------------------------------------------------------------------
_METADATA_ENDPOINTS: list[str] = [
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",
    "fd00:ec2::254",
    "169.254.170.2",
]

_METADATA_IPS: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
for _ep in _METADATA_ENDPOINTS:
    try:
        _METADATA_IPS.add(ipaddress.ip_address(_ep))
    except ValueError:
        pass

_METADATA_HOSTNAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^metadata\.google\.internal$", re.IGNORECASE),
    re.compile(r"^metadata\.goog$", re.IGNORECASE),
    re.compile(r"^metadata$", re.IGNORECASE),
    re.compile(r"^instance-data$", re.IGNORECASE),
    re.compile(r"^kubernetes\.default", re.IGNORECASE),
]

# AWS EC2 IPv6 metadata prefix
_AWS_EC2_IPV6 = ipaddress.ip_network("fd00:ec2::/32")

# ---------------------------------------------------------------------------
# Localhost patterns (regex on hostname string)
# ---------------------------------------------------------------------------
_LOCALHOST_VARIANTS: list[re.Pattern[str]] = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^ip6-localhost$", re.IGNORECASE),
    re.compile(r"^ip6-loopback$", re.IGNORECASE),
    re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^\[?::1\]?$"),
    re.compile(r"^\[?0:0:0:0:0:0:0:1\]?$"),
    re.compile(r"^0x7f", re.IGNORECASE),
    re.compile(r"^2130706433$"),
    re.compile(r"^017700000001$"),
    re.compile(r"^0177\.0+\.0+\.0*1$"),
]

# ---------------------------------------------------------------------------
# Private ranges
# ---------------------------------------------------------------------------
_PRIVATE_RANGES: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
]

# ---------------------------------------------------------------------------
# Dangerous protocol schemes
# ---------------------------------------------------------------------------
_CRITICAL_SCHEMES: frozenset[str] = frozenset({
    "file", "gopher", "dict", "ldap", "ldaps",
    "jar", "netdoc", "php", "phar", "expect",
    "glob", "data", "vbscript", "javascript",
})

_HIGH_SCHEMES: frozenset[str] = frozenset({
    "ftp", "sftp", "tftp", "telnet", "ssh",
    "smb", "svn", "git", "imap", "pop3", "smtp",
})

# ---------------------------------------------------------------------------
# DNS rebinding domains
# ---------------------------------------------------------------------------
_DNS_REBINDING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.nip\.io$", re.IGNORECASE),
    re.compile(r"\.xip\.io$", re.IGNORECASE),
    re.compile(r"\.sslip\.io$", re.IGNORECASE),
    re.compile(r"\.localtest\.me$", re.IGNORECASE),
    re.compile(r"\.lvh\.me$", re.IGNORECASE),
    re.compile(r"\.vcap\.me$", re.IGNORECASE),
    re.compile(r"\.lacolhost\.com$", re.IGNORECASE),
    re.compile(r"\.burpcollaborator\.net$", re.IGNORECASE),
    re.compile(r"\.oastify\.com$", re.IGNORECASE),
    re.compile(r"\.interact\.sh$", re.IGNORECASE),
    re.compile(r"\.requestbin\.net$", re.IGNORECASE),
    re.compile(r"\.ngrok\.io$", re.IGNORECASE),
    re.compile(r"\.ngrok-free\.app$", re.IGNORECASE),
    re.compile(r"\.serveo\.net$", re.IGNORECASE),
    re.compile(r"\.r3dir\.me$", re.IGNORECASE),
]

_TEMPLATE_VAR_RE = re.compile(r"\$\{[^}]+\}|\$[A-Z_]\w*", re.IGNORECASE)


def _parse_ip_octet(part: str) -> int | None:
    """Parse a single IP address octet that may use non-standard encoding.

    Handles: decimal (254), C-style octal (0177), Python-style octal (0o177),
    alternate octal prefixes (o177, q177), and hex (0xFE).
    """
    p = part.strip()
    if not p:
        return None
    try:
        low = p.lower()
        if low.startswith("0x"):
            return int(p, 16)
        if low.startswith("0o") and len(p) > 2 and p[2:].isdigit():
            return int(p[2:], 8)
        if p[0] in "oOqQ" and len(p) > 1 and p[1:].isdigit():
            return int(p[1:], 8)
        if len(p) > 1 and p[0] == "0" and p.isdigit():
            return int(p, 8)
        return int(p)
    except (ValueError, OverflowError):
        return None


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
        """Analyze a URL for SSRF threats."""
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

        # Dangerous schemes checked before hostname (file:// has no host)
        scheme_threat = self._check_dangerous_scheme(parsed.scheme)
        if scheme_threat and not hostname:
            return HTTPAnalysisResult(
                verdict=VerdictType.BLOCK,
                severity=Severity.CRITICAL if parsed.scheme.lower() in _CRITICAL_SCHEMES else Severity.HIGH,
                reasoning=f"SSRF threats detected: {scheme_threat}",
                threats=[scheme_threat],
            )

        if not hostname:
            return HTTPAnalysisResult(
                verdict=VerdictType.ESCALATE,
                severity=Severity.MEDIUM,
                reasoning="No hostname in URL",
                threats=["Missing hostname"],
            )

        # NFKC-normalize hostname (enclosed alphanumerics → ASCII)
        hostname = unicodedata.normalize("NFKC", hostname).lower()

        # Template variable check
        tmpl = self._check_template_variable(hostname)
        if tmpl:
            threats.append(tmpl)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        # 1. Dangerous scheme
        if scheme_threat:
            threats.append(scheme_threat)
            sev = Severity.CRITICAL if parsed.scheme.lower() in _CRITICAL_SCHEMES else Severity.HIGH
            max_severity = _max_sev(max_severity, sev)

        # 2. Metadata endpoints (string match)
        meta = self._check_metadata_endpoint(hostname)
        if meta:
            threats.append(meta)
            max_severity = _max_sev(max_severity, Severity.CRITICAL)

        # 3. Localhost variants (regex)
        localhost = self._check_localhost(hostname)
        if localhost:
            threats.append(localhost)
            max_severity = _max_sev(max_severity, Severity.CRITICAL)

        # 4. Standard private IP check
        private_ip = self._check_private_ip(hostname)
        if private_ip:
            threats.append(private_ip)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        # 5. IP obfuscation resolution
        obfuscated = self._check_ip_obfuscation(hostname)
        if obfuscated:
            threats.append(obfuscated)
            max_severity = _max_sev(max_severity, Severity.CRITICAL)

        # 6. DNS rebinding
        rebinding = self._check_dns_rebinding(hostname)
        if rebinding:
            threats.append(rebinding)
            max_severity = _max_sev(max_severity, Severity.HIGH)

        # 7. URL parser confusion
        confusion = self._check_url_confusion(url, parsed)
        if confusion:
            threats.append(confusion)
            max_severity = _max_sev(max_severity, Severity.HIGH)

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

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_metadata_endpoint(self, hostname: str) -> str | None:
        hostname_lower = hostname.lower().strip("[]")
        for endpoint in _METADATA_ENDPOINTS:
            if hostname_lower == endpoint.lower():
                return f"Cloud metadata endpoint: {endpoint}"
        for pattern in _METADATA_HOSTNAME_PATTERNS:
            if pattern.match(hostname_lower):
                return f"Cloud metadata hostname: {hostname}"
        return None

    def _check_localhost(self, hostname: str) -> str | None:
        for pattern in _LOCALHOST_VARIANTS:
            if pattern.match(hostname):
                return f"Localhost variant detected: {hostname}"
        return None

    def _check_private_ip(self, hostname: str) -> str | None:
        """Check standard-format IPs including IPv4-mapped IPv6."""
        try:
            clean = hostname.strip("[]")
            addr = ipaddress.ip_address(clean)

            # Extract IPv4 from IPv4-mapped IPv6
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                v4 = addr.ipv4_mapped
                if v4.is_private or v4.is_loopback or v4.is_link_local or v4 in _METADATA_IPS:
                    return f"IPv4-mapped IPv6 to internal IP: {hostname} → {v4}"

            # AWS EC2 IPv6 metadata range
            if isinstance(addr, ipaddress.IPv6Address):
                if addr in _AWS_EC2_IPV6:
                    return f"AWS EC2 IPv6 metadata range: {hostname}"

            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return f"Private/internal IP: {hostname}"
            for cidr in _PRIVATE_RANGES:
                if addr in ipaddress.ip_network(cidr):
                    return f"IP in private range {cidr}: {hostname}"
        except ValueError:
            pass
        return None

    def _check_dangerous_scheme(self, scheme: str) -> str | None:
        if not scheme:
            return None
        s = scheme.lower()
        if s in ("http", "https"):
            return None
        if s in _CRITICAL_SCHEMES:
            return f"Critical protocol handler: {s}://"
        return f"Non-HTTP scheme: {s}://"

    def _check_ip_obfuscation(self, hostname: str) -> str | None:
        """Resolve obfuscated IP representations and check for internal targets."""
        resolved = self._resolve_obfuscated_ip(hostname)
        if resolved is None:
            return None

        if resolved.is_loopback:
            return f"Obfuscated loopback IP: {hostname} → {resolved}"
        if resolved.is_private:
            return f"Obfuscated private IP: {hostname} → {resolved}"
        if resolved.is_link_local:
            return f"Obfuscated link-local IP: {hostname} → {resolved}"
        if resolved.is_reserved:
            return f"Obfuscated reserved IP: {hostname} → {resolved}"
        if resolved in _METADATA_IPS:
            return f"Obfuscated metadata IP: {hostname} → {resolved}"
        if resolved.is_unspecified:
            return f"Obfuscated unspecified IP: {hostname} → {resolved}"

        return None

    def _resolve_obfuscated_ip(
        self, hostname: str
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Try to interpret a hostname as an obfuscated IP address.

        Handles: standard IPs, IPv4-mapped IPv6, pure decimal integers,
        hex integers, dotted octal/hex/mixed, and short-form IPs (127.1).
        """
        clean = hostname.strip("[]").strip()
        if not clean:
            return None

        # Standard IP (also handles IPv6)
        try:
            addr = ipaddress.ip_address(clean)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return addr.ipv4_mapped
            return addr
        except ValueError:
            pass

        # Pure decimal integer: 2130706433 → 127.0.0.1
        if clean.isdigit():
            try:
                val = int(clean)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # Hex integer: 0x7f000001 → 127.0.0.1
        if clean.lower().startswith("0x") and "." not in clean:
            try:
                val = int(clean, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # Dotted notation with 2-4 parts (handles short-form + octal/hex/mixed)
        if "." in clean:
            parts = clean.split(".")
            if 2 <= len(parts) <= 4:
                parsed = [_parse_ip_octet(p) for p in parts]
                if all(p is not None for p in parsed):
                    try:
                        return self._expand_ip_parts(parsed)  # type: ignore[arg-type]
                    except (ValueError, OverflowError):
                        pass

        return None

    @staticmethod
    def _expand_ip_parts(parts: list[int]) -> ipaddress.IPv4Address | None:
        """Expand short-form IP parts using POSIX inet_aton rules.

        1 part  → 32-bit address.
        2 parts → a.0.0.b (a = 8 bits, b = 24 bits).
        3 parts → a.b.0.c (a,b = 8 bits each, c = 16 bits).
        4 parts → a.b.c.d (standard).
        """
        if len(parts) == 4:
            if all(0 <= o <= 255 for o in parts):
                return ipaddress.IPv4Address(f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}")
        elif len(parts) == 3:
            a, b, c = parts
            if 0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 65535:
                return ipaddress.IPv4Address((a << 24) | (b << 16) | c)
        elif len(parts) == 2:
            a, b = parts
            if 0 <= a <= 255 and 0 <= b <= 16777215:
                return ipaddress.IPv4Address((a << 24) | b)
        elif len(parts) == 1:
            val = parts[0]
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        return None

    def _check_dns_rebinding(self, hostname: str) -> str | None:
        for pattern in _DNS_REBINDING_PATTERNS:
            if pattern.search(hostname):
                return f"DNS rebinding domain: {hostname}"
        return None

    def _check_url_confusion(self, url: str, parsed: object) -> str | None:
        if url.count("@") > 1:
            return "Multiple @ signs — URL parser confusion"
        netloc = getattr(parsed, "netloc", "") or ""
        if "\\" in netloc:
            return "Backslash in netloc — parser confusion"
        return None

    @staticmethod
    def _check_template_variable(hostname: str) -> str | None:
        if _TEMPLATE_VAR_RE.search(hostname):
            return f"Template variable in hostname: {hostname}"
        return None
