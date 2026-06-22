"""HTTP probing — exposed paths and security headers analysis."""

import logging
import httpx

from backend.core.target_validation import assert_safe_probe_target, TargetValidationError

logger = logging.getLogger(__name__)

_EXPOSED_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/admin",
    "/admin/login",
    "/wp-admin/",
    "/phpmyadmin/",
    "/.htaccess",
    "/web.config",
    "/config.php",
    "/backup.sql",
    "/backup.zip",
    "/dump.sql",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger-ui.html",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/debug",
    "/trace",
    "/console",
    "/__debug__/",
]

_REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS not set — browsers won't enforce HTTPS",
    "X-Frame-Options": "X-Frame-Options missing — site can be embedded in iframes (clickjacking)",
    "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing attacks possible",
    "Content-Security-Policy": "No CSP — XSS attacks have no browser-level mitigation",
    "Referrer-Policy": "No Referrer-Policy — full URLs may leak in referer headers",
}


def check_exposed_paths(base_url: str) -> dict:
    """
    Probes common sensitive paths on a web server.
    Returns a dict with exposed paths, their status codes, and issues list.
    """
    base_url = base_url.rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    # SSRF guard: the host comes from the LLM, so block metadata/loopback/link-local
    # before making any request (cloud IMDS credential theft, scanner-host pivot).
    try:
        assert_safe_probe_target(base_url)
    except TargetValidationError as e:
        return {"error": f"blocked target: {e}", "exposed": [], "issues": []}

    exposed = []
    errors = []

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=False,
            verify=False,          # avoid cert errors on target hosts
            headers={"User-Agent": "Mozilla/5.0 (security-scanner)"},
        ) as client:
            for path in _EXPOSED_PATHS:
                url = f"{base_url}{path}"
                try:
                    r = client.get(url)
                    if r.status_code in (200, 403, 401):
                        entry = {
                            "path": path,
                            "status": r.status_code,
                            "content_length": len(r.content),
                        }
                        # 403/401 means the path exists but is protected — still worth noting
                        if r.status_code == 200:
                            # Peek at content for high-value indicators
                            snippet = r.text[:300] if r.text else ""
                            if any(k in snippet for k in ("DB_", "SECRET", "PASSWORD", "ref:", "HEAD")):
                                entry["sensitive_content"] = True
                        exposed.append(entry)
                except httpx.TransportError:
                    pass
                except Exception as e:
                    errors.append(f"{path}: {e}")
    except Exception as e:
        return {"error": str(e), "exposed": [], "issues": []}

    issues = []
    for e in exposed:
        if e["status"] == 200:
            issues.append(f"Path {e['path']} returns HTTP 200 — may expose sensitive content")
        elif e["status"] in (401, 403):
            issues.append(f"Path {e['path']} exists (HTTP {e['status']}) — confirm it should not be public")

    return {"base_url": base_url, "exposed": exposed, "issues": issues}


def check_security_headers(url: str) -> dict:
    """
    Fetches a URL and evaluates its HTTP security response headers.
    Returns a dict with present/missing headers and issues list.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # SSRF guard (LLM-supplied host). follow_redirects stays off so a 30x cannot
    # bounce the probe to a metadata/loopback address after the initial check.
    try:
        assert_safe_probe_target(url)
    except TargetValidationError as e:
        return {"error": f"blocked target: {e}", "headers": {}, "issues": []}

    try:
        with httpx.Client(timeout=10.0, follow_redirects=False, verify=False) as client:
            r = client.get(url, headers={"User-Agent": "Mozilla/5.0 (security-scanner)"})
    except Exception as e:
        return {"error": str(e), "headers": {}, "issues": []}

    headers = dict(r.headers)
    issues = []

    for header, issue in _REQUIRED_HEADERS.items():
        if header.lower() not in {k.lower() for k in headers}:
            issues.append(issue)

    # HSTS sanity: if present, check max-age is meaningful
    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts:
        issues.append("HSTS max-age=0 disables HSTS — effectively removes the protection")

    # Check for server banner leakage
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    if server:
        issues.append(f"Server header reveals: '{server}' — consider removing to reduce fingerprinting")
    if x_powered:
        issues.append(f"X-Powered-By header reveals: '{x_powered}' — remove to limit stack disclosure")

    return {
        "url": url,
        "status_code": r.status_code,
        "headers": {k: v for k, v in headers.items() if k.lower() in {
            h.lower() for h in list(_REQUIRED_HEADERS.keys()) + ["server", "x-powered-by"]
        }},
        "issues": issues,
    }
