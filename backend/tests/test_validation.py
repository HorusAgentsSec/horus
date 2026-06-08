"""
Tests for the red/blue validation debate.

Two layers: the pure triage gate (core.validation.auto_verdict / confidence_for_verdict) that
decides what is obvious vs what needs debating, and the ValidationAgent applying a (faked) debate
to findings — verifying KEV-active is auto-confirmed without a debate, ambiguous findings get the
judge's verdict + calibrated confidence, and the per-scan debate cap is respected.
"""

from backend.agents.state import AnalyzedFinding, AssetInfo, EnrichedFinding, ScanState
from backend.agents.validation_agent import ValidationAgent
from backend.core import validation


# ── Pure triage gate ────────────────────────────────────────────────────────────

def test_kev_active_is_auto_confirmed():
    assert validation.auto_verdict("high", "active", 0.5) == "confirmed"


def test_info_is_needs_verification():
    assert validation.auto_verdict("info", "none", 0.5) == "needs_verification"


def test_high_confidence_is_confirmed():
    assert validation.auto_verdict("high", "none", 0.95) == "confirmed"


def test_low_confidence_no_exploit_is_needs_verification():
    assert validation.auto_verdict("low", "none", 0.1) == "needs_verification"


def test_ambiguous_goes_to_debate():
    # Mid confidence, no active exploitation, not info → None means "debate it".
    assert validation.auto_verdict("high", "none", 0.7) is None
    assert validation.auto_verdict("medium", "low", 0.6) is None


def test_confidence_for_verdict_is_consistent():
    assert validation.confidence_for_verdict("confirmed", None) >= 0.9
    assert validation.confidence_for_verdict("false_positive", None) <= 0.2


# ── ValidationAgent with a faked debate ─────────────────────────────────────────

def _finding(fid: str, severity="high", confidence=0.7, source_service="nginx 1.18.0"):
    return AnalyzedFinding(
        id=fid, title=f"f{fid}", description="d", severity=severity,
        confidence=confidence, rationale="r", source_service=source_service,
    )


def _state(findings, enriched):
    return ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="web", host="h", type="domain", is_internal=False, tags=[]),
        analyzed_findings=findings, enriched_findings=enriched,
    )


def test_kev_finding_skips_debate(monkeypatch):
    agent = ValidationAgent()
    called = {"n": 0}
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})

    f = _finding("1", confidence=0.6)
    state = _state([f], [EnrichedFinding(finding_id="1", threat_context="", exploitability="active",
                                         public_exploits_exist=True)])
    agent.run(state)

    assert f.verdict == "confirmed"
    assert called["n"] == 0  # no debate spent on a KEV-active finding


def test_ambiguous_finding_gets_debate_verdict(monkeypatch):
    agent = ValidationAgent()
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: {
        "red": "version match is exploitable", "blue": "version-only, likely not reachable",
        "verdict": "false_positive", "confidence": 0.12, "rationale": "version-only guess",
    })

    f = _finding("2", confidence=0.7)
    state = _state([f], [EnrichedFinding(finding_id="2", threat_context="", exploitability="none",
                                         public_exploits_exist=False)])
    agent.run(state)

    assert f.verdict == "false_positive"
    assert f.confidence == 0.12
    assert f.debate["blue"]
    assert f.verdict_rationale == "version-only guess"


def test_debate_cap_is_respected(monkeypatch):
    from backend.core.config import settings
    monkeypatch.setattr(settings, "validation_max_debates", 1)

    agent = ValidationAgent()
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: {
        "verdict": "likely", "confidence": 0.7, "red": "", "blue": "", "rationale": "ok"})

    findings = [_finding(str(i), confidence=0.7) for i in range(3)]
    enriched = [EnrichedFinding(finding_id=str(i), threat_context="", exploitability="none",
                                public_exploits_exist=False) for i in range(3)]
    agent.run(_state(findings, enriched))

    debated = [f for f in findings if f.verdict == "likely"]
    capped = [f for f in findings if f.verdict == "needs_verification"]
    assert len(debated) == 1
    assert len(capped) == 2  # beyond the cap → flagged, not debated


def test_disabled_validation_is_noop(monkeypatch):
    from backend.core.config import settings
    monkeypatch.setattr(settings, "validation_enabled", False)

    f = _finding("9", confidence=0.7)
    ValidationAgent().run(_state([f], []))
    assert f.verdict is None
