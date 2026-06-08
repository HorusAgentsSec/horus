"""Tests for the security response headers."""

from backend.core.security_headers import build_security_headers


def test_core_headers_always_present():
    h = build_security_headers("production")
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "camera=()" in h["Permissions-Policy"]


def test_hsts_only_outside_development():
    assert "Strict-Transport-Security" not in build_security_headers("development")
    assert "Strict-Transport-Security" in build_security_headers("production")
    assert "Strict-Transport-Security" in build_security_headers("staging")


def test_hsts_value():
    hsts = build_security_headers("production")["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
