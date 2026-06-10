"""Unit tests for the deterministic absence/noise classifier (backend/core/noise.py)."""

import pytest

from backend.core.noise import is_absence_finding

# Real titles observed in production data — every one of these must be classified as noise.
NOISE_TITLES = [
    "No DOM-based XSS found on port 8080",
    "No CSRF found on port 443",
    "No CSRF vulnerabilities found on HTTP/80",
    "No stored XSS found on port 80",
    "No file upload forms found on port 443",
    "Nmap DOM-based XSS check on HTTP/80 returned no findings",
    "Nmap http-stored-xss scan returned no vulnerabilities",
    "SMTP server not vulnerable to CVE-2010-4344",
    "Couldn't find any CSRF vulnerabilities",
    "None found during the stored XSS check",
]

# Real findings (including absence-sounding-but-real ones) that must stay visible.
REAL_TITLES = [
    "CVE-2021-32792 in Apache httpd 2.4.41",
    "SSH Server CBC Mode Ciphers Enabled",
    "Self-Signed SSL Certificate",
    "Outdated Apache HTTP Server version with known critical vulnerabilities",
    "Apache httpd 2.4.58 - Multiple CVEs (unverified) on port 8080",
    # Missing security control == a real finding, despite the leading "No".
    "No rate limiting on login endpoint",
    "Missing X-Frame-Options header",
]


@pytest.mark.parametrize("title", NOISE_TITLES)
def test_absence_titles_are_noise(title):
    assert is_absence_finding(title, "info") is True


@pytest.mark.parametrize("title", NOISE_TITLES)
def test_absence_titles_are_noise_regardless_of_severity(title):
    # A confused LLM may mislabel the severity; absence phrasing still wins.
    assert is_absence_finding(title, "medium") is True


@pytest.mark.parametrize("title", REAL_TITLES)
def test_real_findings_are_not_noise(title):
    assert is_absence_finding(title, "info") is False
    assert is_absence_finding(title, "high") is False


def test_scanner_self_noise_only_at_info_severity():
    for title in [
        "CVE-2013-7091 script error on port 8080",
        "nmap http-aspnet-debug script execution failed on HTTP/80",
        "DOM-based XSS check inconclusive",
        "Nmap DOM-based XSS scan on HTTP/80 (negative)",
    ]:
        assert is_absence_finding(title, "info") is True
        # Higher severity means the Analyst saw real signal — keep it visible.
        assert is_absence_finding(title, "medium") is False


def test_edge_cases():
    assert is_absence_finding("", "info") is False
    assert is_absence_finding("No DOM-based XSS found", None) is True
    assert is_absence_finding("nO csrf FOUND on port 80", "INFO") is True
