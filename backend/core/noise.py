"""
Deterministic noise classifier for findings.

Scanners (nmap NSE scripts in particular) emit "absence of finding" output — "No DOM-based XSS
found on port 8080", "not vulnerable to CVE-…", script errors — and the Analyst sometimes lets
them through as info findings. They drown the real signal in the Findings list, so we flag them
as noise at persist time and GET /api/findings hides them by default.

Keep the patterns here in sync with the backfill in
supabase/migrations/20260610100000_findings_noise.sql.
"""

import re

# Absence-of-vulnerability phrasing → noise regardless of severity.
_ABSENCE_PATTERNS = [
    re.compile(r"\bnot\s+vulnerable\b", re.I),
    re.compile(r"\b(returned|reported|revealed)\s+no\s+(finding|vulnerabilit|issue|result)", re.I),
    re.compile(r"\b(couldn'?t|could\s+not|unable\s+to)\s+(find|detect|identify)\b", re.I),
    re.compile(r"\bnone\s+(found|detected|identified)\b", re.I),
]

# Only noise at info severity. A leading "No ... found" reads as scanner absence
# ("No DOM-based XSS found on port 8080"), but at medium/high the same phrasing is usually a
# real missing control ("No rate limiting found on login endpoint") that must stay visible —
# so gating it on info is what keeps the broad leading-"No" pattern from hiding real findings.
# Also covers scanner self-noise (script crashed, inconclusive, negative).
_INFO_NOISE_PATTERNS = [
    re.compile(r"^\s*no\s+.*\b(found|detected|identified|observed)\b", re.I),
    re.compile(r"\bscript\s+(error|execution\s+failed)\b", re.I),
    re.compile(r"\binconclusive\b", re.I),
    re.compile(r"\(negative\)", re.I),
]


def is_absence_finding(title: str, severity: str | None = None) -> bool:
    """True when a finding title reads as "we looked and found nothing" (or pure scanner
    noise at info severity) and should be hidden from the default Findings list."""
    if not title:
        return False
    if any(p.search(title) for p in _ABSENCE_PATTERNS):
        return True
    if (severity or "").lower() == "info":
        return any(p.search(title) for p in _INFO_NOISE_PATTERNS)
    return False
