"""
Scan-target validation — the foundational guard that stops Horus from
being abused as an attack proxy (SSRF) or having its scanners hijacked via
argument injection.

Threat model:
  - SSRF to cloud metadata (169.254.169.254 → IAM credential theft)
  - Scanning infrastructure the org does not own (loopback, third-party internal IPs)
  - Argument injection into nmap/nuclei (host = "-oX /etc/passwd")
  - Malformed hosts that break the subprocess invocation

This is a blue-team tool, so scanning *internal* assets is legitimate — but only
when the asset is explicitly flagged is_internal. External assets must never
resolve to private/reserved ranges.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

# Cloud metadata endpoints — never a legitimate scan target, classic SSRF pivot.
ALWAYS_BLOCKED_IPS = {
    "169.254.169.254",   # AWS / GCP / Azure IMDS
    "100.100.100.200",   # Alibaba Cloud metadata
    "fd00:ec2::254",     # AWS IMDSv2 IPv6
}

# A conservative hostname/IP charset. Anything outside this is rejected outright,
# which also closes argument-injection (leading '-') and shell metacharacters.
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")


class TargetValidationError(ValueError):
    """Raised when a scan target is unsafe or malformed."""


def _extract_host(raw: str) -> str:
    """Accepts a bare host, host:port, or full URL and returns the hostname."""
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or ""
    # Strip a :port suffix if present (but keep IPv6 brackets intact)
    if raw.startswith("["):  # IPv6 literal like [::1]:80
        return raw.split("]")[0].lstrip("[")
    if raw.count(":") == 1:  # host:port
        return raw.split(":")[0]
    return raw


def _ip_is_unsafe(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip_str in ALWAYS_BLOCKED_IPS:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_scan_target(host: str, is_internal: bool = False) -> str:
    """
    Validates and normalizes a scan target. Returns the clean hostname.
    Raises TargetValidationError if the target is unsafe.

    is_internal=True relaxes the private-range check (the org owns the asset),
    but cloud metadata IPs and argument injection are blocked unconditionally.
    """
    if not host or not host.strip():
        raise TargetValidationError("Host cannot be empty")

    extracted = _extract_host(host)
    if not extracted:
        raise TargetValidationError(f"Could not parse a hostname from '{host}'")

    if extracted.startswith("-"):
        raise TargetValidationError(
            "Host cannot start with '-' (blocked: scanner argument injection)"
        )

    if not _HOST_RE.match(extracted):
        raise TargetValidationError(
            f"Host '{extracted}' contains illegal characters"
        )

    # Cloud metadata is always forbidden, even for internal assets
    if extracted in ALWAYS_BLOCKED_IPS:
        raise TargetValidationError(
            f"Host '{extracted}' is a cloud metadata endpoint and can never be scanned"
        )

    # If the host is a literal IP, check it directly
    is_ip = False
    try:
        ipaddress.ip_address(extracted)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        if _ip_is_unsafe(extracted) and not is_internal:
            raise TargetValidationError(
                f"'{extracted}' is a private/reserved address; mark the asset as "
                f"internal if you own it and intend to scan it"
            )
        return extracted

    # Hostname: best-effort resolution to catch DNS pointing at unsafe ranges
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(extracted, None)}
    except (socket.gaierror, UnicodeError):
        # Unresolvable at validation time — allow (may resolve later / be offline),
        # the scanner itself will simply find nothing.
        return extracted

    for ip_str in resolved:
        if ip_str in ALWAYS_BLOCKED_IPS:
            raise TargetValidationError(
                f"'{extracted}' resolves to cloud metadata ({ip_str}) — blocked"
            )
        if _ip_is_unsafe(ip_str) and not is_internal:
            raise TargetValidationError(
                f"'{extracted}' resolves to a private/reserved address ({ip_str}); "
                f"mark the asset as internal if you own it"
            )

    return extracted
