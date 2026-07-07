"""
Tests for the red/blue validation debate.

Two layers: the pure triage gate (core.validation.auto_verdict / confidence_for_verdict) that
decides what is obvious vs what needs debating, and the ValidationAgent applying a (faked) debate
to findings — verifying KEV-active is auto-confirmed without a debate, ambiguous findings get the
judge's verdict + calibrated confidence, and the per-scan debate cap is respected.
"""

import pytest

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


# ── Rebuttal round (critical + internet-facing only) ────────────────────────────

def _round_one():
    return {"red": "exploitable now", "blue": "maybe not reachable",
            "verdict": "likely", "confidence": 0.6, "rationale": "initial read"}


def test_critical_internet_facing_finding_gets_rebuttal_round(monkeypatch):
    agent = ValidationAgent()
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: _round_one())
    rebuttal_calls = {"n": 0}

    def fake_rebuttal(*a, **k):
        rebuttal_calls["n"] += 1
        return {"red_rebuttal": "still exploitable", "blue_rebuttal": "conceded",
                "verdict": "confirmed", "confidence": 0.95, "rationale": "blue conceded"}

    monkeypatch.setattr(agent, "_rebuttal_round", fake_rebuttal)

    f = _finding("10", severity="critical", confidence=0.7)
    state = _state([f], [EnrichedFinding(finding_id="10", threat_context="", exploitability="none",
                                         public_exploits_exist=False)])
    state.asset.is_internal = False  # internet-facing
    agent.run(state)

    assert rebuttal_calls["n"] == 1
    assert f.verdict == "confirmed"
    assert f.confidence == 0.95
    assert f.verdict_rationale == "blue conceded"
    assert f.debate["red"] == "exploitable now"  # round one preserved
    assert f.debate["red_rebuttal"] == "still exploitable"
    assert f.debate["blue_rebuttal"] == "conceded"


def test_non_critical_finding_skips_rebuttal_round(monkeypatch):
    agent = ValidationAgent()
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: _round_one())
    monkeypatch.setattr(agent, "_rebuttal_round", lambda *a, **k: pytest.fail("should not be called"))

    f = _finding("11", severity="high", confidence=0.7)  # not critical
    state = _state([f], [EnrichedFinding(finding_id="11", threat_context="", exploitability="none",
                                         public_exploits_exist=False)])
    agent.run(state)

    assert f.verdict == "likely"  # round one's verdict stands
    assert "red_rebuttal" not in f.debate


def test_critical_finding_on_internal_asset_skips_rebuttal_round(monkeypatch):
    agent = ValidationAgent()
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: _round_one())
    monkeypatch.setattr(agent, "_rebuttal_round", lambda *a, **k: pytest.fail("should not be called"))

    f = _finding("12", severity="critical", confidence=0.7)
    state = _state([f], [EnrichedFinding(finding_id="12", threat_context="", exploitability="none",
                                         public_exploits_exist=False)])
    state.asset.is_internal = True  # not internet-facing
    agent.run(state)

    assert f.verdict == "likely"


def test_rebuttal_round_failure_keeps_round_one_verdict(monkeypatch):
    agent = ValidationAgent()
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: _round_one())
    monkeypatch.setattr(agent, "_rebuttal_round",
                         lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider timeout")))

    f = _finding("13", severity="critical", confidence=0.7)
    state = _state([f], [EnrichedFinding(finding_id="13", threat_context="", exploitability="none",
                                         public_exploits_exist=False)])
    state.asset.is_internal = False
    agent.run(state)

    assert f.verdict == "likely"  # round one's verdict survives the failed rebuttal
    assert "red_rebuttal" not in f.debate
