"""
Security response headers — defense-in-depth hardening applied to every API response.

The backend only serves JSON (the React app is served separately by Vite/its host), so
the CSP is locked all the way down: nothing should ever be loaded from an API response, and
it must never be framed. HSTS is emitted only outside development, since forcing HTTPS on a
plaintext localhost would make the dev site unreachable after one visit.

Kept as a pure function so the header set is unit-testable without the web framework.
"""


def build_security_headers(environment: str) -> dict[str, str]:
    """Returns the security headers to attach to responses for the given environment."""
    headers = {
        # No MIME sniffing — responses are taken at their declared Content-Type.
        "X-Content-Type-Options": "nosniff",
        # This is a JSON API; it must never be embedded in a frame (clickjacking).
        "X-Frame-Options": "DENY",
        # Don't leak the API URL (which can carry ids) to other origins.
        "Referrer-Policy": "no-referrer",
        # Lock down the response itself: load nothing, allow no framing.
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        # Isolate the browsing context group.
        "Cross-Origin-Opener-Policy": "same-origin",
        # Drop access to powerful browser features by default.
        "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
    }

    # Only enforce HTTPS where the deployment actually serves it.
    if environment != "development":
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return headers
