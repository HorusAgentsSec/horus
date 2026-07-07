"""
Finding validation — the deterministic gate in front of the red/blue debate.

The debate (ValidationAgent) is the adversarial step that calibrates a finding's confidence and
catches false positives: a red-team advocate argues it's real and exploitable, a blue-team skeptic
argues it's noise or unreachable, and a judge rules. That's an LLM call, so we don't spend it where
the answer is already certain. This module is the pure triage that decides:

  - auto_verdict(...) -> a verdict when the call is obvious (KEV-active is real; info is noise;
    a very-confident analyst result needs no second-guessing), or None when the finding is genuinely
    ambiguous and worth debating (version-only CVE correlation, nmap http-* "potential" scripts).

Pure and unit-tested; no LLM, no DB. The ValidationAgent owns the actual debate and applies results.
"""

# Verdicts, least → most "this is a real, actionable finding".
VERDICTS = ("false_positive", "needs_verification", "likely", "confirmed")

# An analyst confidence at/above this is treated as settled — no debate needed.
HIGH_CONFIDENCE = 0.9
# Below this, with no exploitation signal, it's noise we leave for verification rather than
# burning a debate on it.
LOW_CONFIDENCE = 0.2


def auto_verdict(severity: str | None, exploitability: str | None, confidence: float | None) -> str | None:
    """Deterministic verdict for the clear-cut cases, or None when the finding should go to the
    red/blue debate.

      - Active exploitation (CISA KEV) -> confirmed. Real by definition; never waste a debate.
      - info severity                  -> needs_verification (don't debate noise; don't claim real).
      - confidence >= HIGH_CONFIDENCE  -> confirmed (the analyst is already sure).
      - confidence <= LOW_CONFIDENCE and no exploitation -> needs_verification.
      - otherwise                      -> None  (ambiguous → debate).
    """
    exp = (exploitability or "none").lower()
    conf = confidence if confidence is not None else 0.5

    if exp == "active":
        return "confirmed"
    if (severity or "").lower() == "info":
        return "needs_verification"
    if conf >= HIGH_CONFIDENCE:
        return "confirmed"
    if conf <= LOW_CONFIDENCE and exp == "none":
        return "needs_verification"
    return None


def confidence_for_verdict(verdict: str, current: float | None) -> float:
    """A sane confidence floor/ceiling per verdict, used when the debate doesn't return one.
    Keeps the persisted confidence consistent with the verdict label."""
    base = {
        "confirmed": 0.9,
        "likely": 0.7,
        "needs_verification": 0.4,
        "false_positive": 0.1,
    }.get(verdict, current if current is not None else 0.5)
    return round(max(0.0, min(1.0, base)), 2)
