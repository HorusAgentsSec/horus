"""
CPE -> CVE correlation against NVD, on-demand with a local cache.

Given a service detected on an asset (e.g. product="nginx", version="1.18.0"),
ask NVD which CVEs apply to that product+version. NVD performs the version-range
matching server-side (correct + maintained), so we don't reimplement it. Results
are cached in cpe_lookup_cache; the per-CVE CVSS is folded into cve_intel so all
severity/exploit data (KEV + EPSS + CVSS) lives in one place for the pipeline.

Known v1 limitation: we match by product name with a wildcard vendor. Products whose
NVD name differs from the scanner's label (e.g. nmap "Apache httpd" vs NVD
"http_server") won't match until we add a product-alias map.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone, timedelta

import httpx

from backend.core.config import settings
from backend.core.supabase_client import supabase  # service-role: bypasses RLS

logger = logging.getLogger(__name__)

# NVD rate limiting: enforce a minimum interval between requests across all threads
# (the scan pipeline runs in a thread pool, so concurrent scans could otherwise burst).
_rate_lock = threading.Lock()
_last_call = 0.0


def _nvd_get(params: dict) -> dict:
    global _last_call
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    with _rate_lock:
        wait = settings.nvd_min_interval_seconds - (time.monotonic() - _last_call)
        if wait > 0:
            time.sleep(wait)
        resp = httpx.get(
            settings.nvd_api_base,
            params=params,
            headers=headers,
            timeout=settings.nvd_timeout_seconds,
            follow_redirects=True,
        )
        _last_call = time.monotonic()
    resp.raise_for_status()
    return resp.json()


def _normalize_product(name: str) -> str:
    """nmap/scanner product label -> CPE-style product token (best effort)."""
    return name.strip().lower().replace(" ", "_")


def _normalize_version(version: str) -> str:
    """Scanner version labels are free text — e.g. "8.2p1 Ubuntu 4ubuntu0.13" or
    "9.6.0 or later". A CPE version field must be a single token, so keep only the
    leading version-looking token (dropping distro/qualifier noise) and require it
    to start with a digit; otherwise NVD rejects the CPE with a 404."""
    version = (version or "").strip()
    if not version:
        return ""
    token = version.split()[0]  # "8.2p1 Ubuntu ..." -> "8.2p1"; "9.6.0 or later" -> "9.6.0"
    match = re.match(r"[0-9][0-9A-Za-z._\-]*", token)
    return match.group(0) if match else ""


def build_match_string(product: str, version: str, vendor: str = "*") -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


# Scanner product label (normalized) -> (CPE vendor, CPE product). Scanners and NVD
# disagree on names — the classic case is nmap "Apache httpd" vs NVD "http_server".
# Fixing the product token (and pinning vendor where it's stable) lifts correlation
# coverage well beyond the wildcard-vendor default. Vendor "*" = product token is the
# fix but the vendor is ambiguous/varied (e.g. nginx).
PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "apache_httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "apache_tomcat": ("apache", "tomcat"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("*", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "microsoft_iis_httpd": ("microsoft", "internet_information_services"),
    "microsoft_iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "vsftpd": ("*", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("*", "pure-ftpd"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "isc_bind": ("isc", "bind"),
    "bind": ("isc", "bind"),
    "samba": ("samba", "samba"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "haproxy": ("haproxy", "haproxy"),
    "openssl": ("openssl", "openssl"),
    "wordpress": ("wordpress", "wordpress"),
    # Additional common service products
    "openssh_server": ("openbsd", "openssh"),
    "dropbear_sshd": ("matt_johnston", "dropbear_ssh_server"),
    "filezilla_server": ("filezilla-project", "filezilla_server"),
    "wuftpd": ("washington_university", "wu-ftpd"),
    "sendmail": ("sendmail", "sendmail"),
    "courier_imapd": ("courier", "imap"),
    "courier_pop3d": ("courier", "pop3"),
    "cyrus_imapd": ("carnegie_mellon_university", "cyrus_imap"),
    "cyrus_pop3d": ("carnegie_mellon_university", "cyrus_imap"),
    "isc_dhcpd": ("isc", "dhcp"),
    "squid": ("squid-cache", "squid"),
    "varnish": ("varnish-cache", "varnish"),
    "jenkins": ("jenkins", "jenkins"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "memcached": ("memcached", "memcached"),
}

# nmap service name (the `name` attribute in <service>) -> product hint when
# nmap doesn't detect a product name. Allows basic correlation from service type alone.
SERVICE_NAME_FALLBACKS: dict[str, str] = {
    "ssh": "openssh",
    "ftp": "vsftpd",
    "smtp": "postfix",
    "pop3": "dovecot",
    "imap": "dovecot",
    "http": "apache",
    "https": "apache",
    "mysql": "mysql",
    "postgres": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "memcache": "memcached",
    "telnet": "netkit-telnet",
}


def _resolve_cpe(product: str) -> tuple[str, str]:
    """
    Map a scanner product label to (vendor, product) in CPE terms. Tries the full
    normalized name, then the first token (so "Dovecot imapd" -> dovecot), and finally
    falls back to wildcard vendor + the raw token.
    """
    norm = _normalize_product(product)
    if norm in PRODUCT_ALIASES:
        return PRODUCT_ALIASES[norm]
    first = norm.split("_")[0]
    if first in PRODUCT_ALIASES:
        return PRODUCT_ALIASES[first]
    return ("*", norm)


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _extract_cvss(cve: dict) -> tuple[float | None, str | None]:
    """Best available CVSS base score + severity (prefer v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        if score is None:
            continue
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or _severity_from_score(score)
        return float(score), severity.lower()
    return None, None


def _query_nvd(product: str, version: str, vendor: str) -> list[tuple[str, float | None, str | None]]:
    """Returns [(cve_id, cvss_score, cvss_severity), ...] for the product+version."""
    match = build_match_string(product, version, vendor)
    results: list[tuple[str, float | None, str | None]] = []
    start = 0
    while True:
        data = _nvd_get(
            {"virtualMatchString": match, "resultsPerPage": 2000, "startIndex": start}
        )
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            score, sev = _extract_cvss(cve)
            results.append((cve["id"], score, sev))
        total = data.get("totalResults", 0)
        start += data.get("resultsPerPage", 0)
        if start >= total or not data.get("vulnerabilities"):
            break
    return results


def _enrich_cve_intel(rows: list[tuple[str, float | None, str | None]]) -> None:
    """Fold NVD CVSS into cve_intel WITHOUT touching KEV/EPSS columns (merge-duplicates
    only updates the keys we send)."""
    now = datetime.now(timezone.utc).isoformat()
    payload = [
        {"cve_id": cid, "cvss_score": score, "cvss_severity": sev, "updated_at": now}
        for cid, score, sev in rows
        if score is not None
    ]
    if payload:
        supabase.table("cve_intel").upsert(payload, on_conflict="cve_id").execute()


def cves_for(product: str, version: str, vendor: str | None = None, refresh: bool = False) -> list[str]:
    """
    Returns the CVE ids applicable to a product+version. Reads the local cache when
    fresh; otherwise queries NVD, caches the answer, and enriches cve_intel with CVSS.

    When vendor is None, the scanner product label is resolved through PRODUCT_ALIASES
    (e.g. "Apache httpd" -> vendor=apache, product=http_server) for better coverage.
    """
    version = _normalize_version(version)
    if not product or not version:
        return []
    if vendor is None:
        vendor, product = _resolve_cpe(product)
    else:
        product = _normalize_product(product)
    cpe_key = f"{vendor}:{product}:{version}"

    if not refresh:
        cached = (
            supabase.table("cpe_lookup_cache").select("*").eq("cpe_key", cpe_key).execute()
        )
        if cached.data:
            row = cached.data[0]
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"])
            if age < timedelta(days=settings.cpe_cache_max_age_days):
                return row["cve_ids"]

    try:
        nvd_rows = _query_nvd(product, version, vendor)
    except Exception as e:
        logger.warning("NVD lookup failed for %s: %s", cpe_key, e)
        # Fall back to any stale cache rather than nothing.
        cached = (
            supabase.table("cpe_lookup_cache").select("cve_ids").eq("cpe_key", cpe_key).execute()
        )
        return cached.data[0]["cve_ids"] if cached.data else []

    cve_ids = sorted({cid for cid, _, _ in nvd_rows})
    _enrich_cve_intel(nvd_rows)
    supabase.table("cpe_lookup_cache").upsert(
        {
            "cpe_key": cpe_key,
            "cve_ids": cve_ids,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        },
        on_conflict="cpe_key",
    ).execute()
    logger.info("CPE correlation: %s -> %d CVEs", cpe_key, len(cve_ids))
    return cve_ids


def correlate_services(services: list[dict]) -> dict[str, list[str]]:
    """
    Batch helper for the pipeline. `services` is [{"product": ..., "version": ...,
    "service": ..., "extrainfo": ...}, ...].
    Returns {"product version": [cve_ids]} for each service we could resolve.

    Falls back to service-name-derived product when nmap doesn't detect a product name
    (e.g. service="ftp" + version="3.0.3" → tries product "vsftpd"). The version is
    stripped of packaging noise (distro qualifiers) before lookup.
    """
    out: dict[str, list[str]] = {}
    for svc in services:
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip()
        service_name = (svc.get("service") or "").strip().lower()
        extrainfo = (svc.get("extrainfo") or "").strip()

        # When the version is empty but extrainfo carries version info (e.g. nmap reports
        # "Telnet" as product and "Linux telnetd" in extrainfo), try extrainfo as version.
        if not version and extrainfo:
            version = extrainfo

        # Strip distro packaging qualifiers from version (e.g. "8.2p1 Ubuntu 4ubuntu0.13"
        # → "8.2p1") so NVD CPE lookup gets a clean version token.
        version = _normalize_version(version)
        if not version:
            continue

        if product:
            label = f"{product} {version}"
            out[label] = cves_for(product, version)
        elif service_name and service_name in SERVICE_NAME_FALLBACKS:
            # No product detected — use service-name-derived fallback product.
            fallback_product = SERVICE_NAME_FALLBACKS[service_name]
            label = f"{fallback_product} {version} (via {service_name})"
            out[label] = cves_for(fallback_product, version)

    return out


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    import sys

    prod = sys.argv[1] if len(sys.argv) > 1 else "nginx"
    ver = sys.argv[2] if len(sys.argv) > 2 else "1.18.0"
    print(f"{prod} {ver} -> {cves_for(prod, ver, refresh=True)}")
