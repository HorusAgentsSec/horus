"""Unit tests for the deterministic absence/noise classifier (backend/core/noise.py)."""

import pytest

from backend.core.noise import is_absence_finding

# Titles that unconditionally read as an absence-of-vulnerability statement
# (_ABSENCE_PATTERNS in noise.py) — noise at any severity.
UNCONDITIONAL_NOISE_TITLES = [
    "Nmap DOM-based XSS check on HTTP/80 returned no findings",
    "Nmap http-stored-xss scan returned no vulnerabilities",
    "SMTP server not vulnerable to CVE-2010-4344",
    "Couldn't find any CSRF vulnerabilities",
    "None found during the stored XSS check",
]

# Titles that only match the broad leading "No ... found" heuristic (_INFO_NOISE_PATTERNS).
# Deliberately noise ONLY at info severity: the same phrasing at medium/high usually means a
# real missing control (e.g. "No rate limiting found on login endpoint") and must stay visible,
# so this heuristic is intentionally not "regardless of severity".
INFO_ONLY_NOISE_TITLES = [
    "No DOM-based XSS found on port 8080",
    "No CSRF found on port 443",
    "No CSRF vulnerabilities found on HTTP/80",
    "No stored XSS found on port 80",
    "No file upload forms found on port 443",
]

NOISE_TITLES = UNCONDITIONAL_NOISE_TITLES + INFO_ONLY_NOISE_TITLES

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


@pytest.mark.parametrize("title", UNCONDITIONAL_NOISE_TITLES)
def test_absence_titles_are_noise_regardless_of_severity(title):
    # A confused LLM may mislabel the severity; absence phrasing still wins.
    assert is_absence_finding(title, "medium") is True


@pytest.mark.parametrize("title", INFO_ONLY_NOISE_TITLES)
def test_info_only_noise_titles_stay_visible_at_higher_severity(title):
    # The leading "No ... found" heuristic is scoped to info on purpose (see noise.py) so it
    # can't hide a real missing-control finding the Analyst upgraded to medium/high.
    assert is_absence_finding(title, "medium") is False


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
    # No severity given → not "info", so the info-only heuristic doesn't fire (by design).
    assert is_absence_finding("No DOM-based XSS found", None) is False
    assert is_absence_finding("No DOM-based XSS found", "info") is True
    assert is_absence_finding("nO csrf FOUND on port 80", "INFO") is True
