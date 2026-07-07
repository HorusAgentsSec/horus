"""
Active validation — a light, opt-in probe that confirms a version-only finding against the
live service before we spend an LLM debate on it.

Most of our false positives are version-only CVE correlations: nmap once saw "nginx 1.18.0" on a
port, we matched its CVEs, but the package may have been patched without a version bump, or the
service may be long gone. The red/blue debate guesses; this probe *checks*. It makes ONE cheap,
non-destructive connection to the asset (an HTTP GET or a TCP banner read — never an exploit
payload) and asks: is that exact version still exposed right now?

  - version still in the banner  -> confirmed     (the vulnerable version is live; not a stale guess)
  - service unreachable          -> false_positive (port closed / host gone; the inventory was stale)
  - reachable but no version      -> None          (inconclusive; leave it for the debate)

Off by default (`active_validation_enabled`): it touches the network, so it's an explicit opt-in.
The decision logic (assess_probe / probe_to_verdict) is pure and unit-tested; the transport is
injectable so tests never open a socket.
"""

import http.client
import socket
import ssl
from typing import Callable

# Outcomes of a probe, independent of how we map them to a verdict.
CONFIRMED_VERSION = "confirmed_version"
SERVICE_PRESENT = "service_present"
ABSENT = "absent"

# Ports we speak HTTP(S) to; everything else gets a raw TCP banner read.
HTTPS_PORTS = {443, 8443}
HTTP_PORTS = {80, 8080, 8000, 8888}

# (reachable, banner) — the only thing the pure layer needs from the network.
Fetcher = Callable[[str, int, float], tuple[bool, str]]


def assess_probe(reachable: bool, banner: str, product: str, version: str) -> str:
    """Pure: turn a (reachable, banner) observation into a probe outcome.

    A confirmed match needs the version string present AND, when we know the product, a product
    token in the banner too — so a bare "1.0" in some unrelated header can't fake a confirmation.
    """
    if not reachable:
        return ABSENT
    b = banner.lower()
    ver = (version or "").strip().lower()
    if ver and ver in b:
        prod_token = (product or "").strip().lower().split()[0] if product else ""
        if not prod_token or prod_token in b:
            return CONFIRMED_VERSION
    return SERVICE_PRESENT


def probe_to_verdict(outcome: str) -> tuple[str, str] | None:
    """Pure: map a probe outcome to (verdict, rationale), or None to defer to the debate."""
    if outcome == CONFIRMED_VERSION:
        return ("confirmed", "Active probe confirmed the vulnerable version is still exposed.")
    if outcome == ABSENT:
        return ("false_positive", "Active probe found the service unreachable — likely stale or patched.")
    return None  # service_present → inconclusive, let the debate decide


def _default_fetcher(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Stdlib transport: HTTP(S) GET for web ports, raw TCP banner read otherwise.

    Returns (reachable, banner). Non-destructive: a single GET "/" or a passive banner read,
    never a payload. Any failure to connect → (False, "")."""
    if port in HTTPS_PORTS or port in HTTP_PORTS:
        is_https = port in HTTPS_PORTS
        conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
        kwargs = {"timeout": timeout}
        if is_https:
            kwargs["context"] = ssl._create_unverified_context()  # we read the banner, not trust the cert
        conn = conn_cls(host, port, **kwargs)
        try:
            conn.request("GET", "/", headers={"User-Agent": "Horus-ActiveValidation/1.0"})
            resp = conn.getresponse()
            server = resp.getheader("Server", "") or ""
            return True, f"{server} {resp.status}"
        except (OSError, http.client.HTTPException):
            return False, ""
        finally:
            conn.close()

    # Raw TCP: connect, then try to read a greeting banner (SSH/FTP/SMTP send one unprompted).
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except (socket.timeout, OSError):
                data = b""
            return True, data.decode("latin-1", "replace").strip()
    except OSError:
        return False, ""


def probe_service(
    host: str,
    port: int,
    product: str,
    version: str,
    timeout: float = 3.0,
    fetcher: Fetcher = _default_fetcher,
) -> tuple[str, str] | None:
    """Probe `host:port` and return (verdict, rationale) when conclusive, else None.

    `fetcher` is injected in tests so no real socket is opened. Best-effort: any transport error
    surfaces as ABSENT via the fetcher, never raises."""
    reachable, banner = fetcher(host, port, timeout)
    return probe_to_verdict(assess_probe(reachable, banner, product, version))
