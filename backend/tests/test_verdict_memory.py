"""
Tests for the verdict memory (reflection loop).

Covers the pure `finding_signature` (must be stable and generalize across assets/scans) and the
ValidationAgent applying a recalled human prior: a signature a teammate marked false_positive is
auto-suppressed without a debate; one marked confirmed is trusted; and KEV-active overrides a stale
false-positive memory.
"""

from backend.agents.state import AnalyzedFinding, AssetInfo, EnrichedFinding, ScanState
from backend.agents.validation_agent import ValidationAgent
from backend.core import verdict_memory


# ── finding_signature ───────────────────────────────────────────────────────────

def test_signature_prefers_service_version_stripped():
    assert verdict_memory.finding_signature(source_service="nginx 1.18.0") == "svc:nginx"
    # Same product, different version/asset → same signature (the whole point).
    assert verdict_memory.finding_signature(source_service="nginx 1.25.3") == "svc:nginx"


def test_signature_falls_back_to_cve_then_title():
    assert verdict_memory.finding_signature(cve_ids=["CVE-2023-9", "CVE-2021-1"]) == "cve:CVE-2021-1"
    assert verdict_memory.finding_signature(title="Potential CSRF in form") == "title:potential-csrf-in-form"


def test_signature_is_stable_between_recording_and_recall_shapes():
    # Recording side passes a DB-style dict; recall side passes AnalyzedFinding fields. Same key.
    from_db = verdict_memory.finding_signature(
        source_service=({"source_service": "apache 2.4.41"}).get("source_service"),
        cve_ids=["CVE-2021-1"], title="x",
    )
    from_agent = verdict_memory.finding_signature(
        source_service="apache 2.4.41", cve_ids=["CVE-2021-1"], title="x",
    )
    assert from_db == from_agent == "svc:apache"


def test_status_to_verdict_mapping():
    assert verdict_memory.STATUS_TO_VERDICT["false_positive"] == "false_positive"
    assert verdict_memory.STATUS_TO_VERDICT["resolved"] == "confirmed"
    assert verdict_memory.STATUS_TO_VERDICT["accepted_risk"] == "confirmed"
    assert "open" not in verdict_memory.STATUS_TO_VERDICT


# ── ValidationAgent applying recalled priors ────────────────────────────────────

def _finding(fid, source_service="nginx 1.18.0", confidence=0.7):
    return AnalyzedFinding(id=fid, title=f"f{fid}", description="d", severity="high",
                           confidence=confidence, rationale="r", source_service=source_service)


def _state(findings, enriched):
    return ScanState(
        scan_id="s", org_id="org-1",
        asset=AssetInfo(id="a", name="web", host="h", type="domain", is_internal=False, tags=[]),
        analyzed_findings=findings, enriched_findings=enriched,
    )


def test_recalled_false_positive_suppresses_without_debate(monkeypatch):
    monkeypatch.setattr(verdict_memory, "recall", lambda org, sigs, client=None: {"svc:nginx": "false_positive"})
    agent = ValidationAgent()
    debated = {"n": 0}
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: debated.__setitem__("n", debated["n"] + 1) or {})

    f = _finding("1")
    agent.run(_state([f], [EnrichedFinding(finding_id="1", threat_context="", exploitability="none",
                                           public_exploits_exist=False)]))

    assert f.verdict == "false_positive"
    assert debated["n"] == 0
    assert "false positive" in f.verdict_rationale


def test_recalled_confirmed_is_trusted(monkeypatch):
    monkeypatch.setattr(verdict_memory, "recall", lambda org, sigs, client=None: {"svc:nginx": "confirmed"})
    agent = ValidationAgent()
    f = _finding("2")
    agent.run(_state([f], [EnrichedFinding(finding_id="2", threat_context="", exploitability="none",
                                           public_exploits_exist=False)]))
    assert f.verdict == "confirmed"


def test_kev_active_overrides_stale_false_positive_memory(monkeypatch):
    monkeypatch.setattr(verdict_memory, "recall", lambda org, sigs, client=None: {"svc:nginx": "false_positive"})
    agent = ValidationAgent()
    f = _finding("3")
    agent.run(_state([f], [EnrichedFinding(finding_id="3", threat_context="", exploitability="active",
                                           public_exploits_exist=True)]))
    # Exploited in the wild wins over an old false-positive call.
    assert f.verdict == "confirmed"


# ── Community flywheel: cross-org priors ────────────────────────────────────────

def _no_org_memory(monkeypatch):
    monkeypatch.setattr(verdict_memory, "recall", lambda *a, **k: {})


def test_community_prior_applies_when_no_org_memory(monkeypatch):
    _no_org_memory(monkeypatch)
    monkeypatch.setattr(verdict_memory, "recall_community", lambda sigs, client=None: {"svc:nginx": "false_positive"})
    agent = ValidationAgent()
    debated = {"n": 0}
    monkeypatch.setattr(agent, "_debate", lambda *a, **k: debated.__setitem__("n", debated["n"] + 1) or {})

    f = _finding("1")
    agent.run(_state([f], [EnrichedFinding(finding_id="1", threat_context="", exploitability="none",
                                           public_exploits_exist=False)]))

    assert f.verdict == "false_positive"
    assert debated["n"] == 0
    assert "community" in (f.verdict_rationale or "").lower()


def test_org_memory_wins_over_community(monkeypatch):
    # This org confirmed it; the community thinks it's a false positive → the org's call wins.
    monkeypatch.setattr(verdict_memory, "recall", lambda *a, **k: {"svc:nginx": "confirmed"})
    monkeypatch.setattr(verdict_memory, "recall_community", lambda sigs, client=None: {"svc:nginx": "false_positive"})
    agent = ValidationAgent()
    f = _finding("2")
    agent.run(_state([f], [EnrichedFinding(finding_id="2", threat_context="", exploitability="none",
                                           public_exploits_exist=False)]))
    assert f.verdict == "confirmed"
    assert "your team" in (f.verdict_rationale or "").lower()


def test_kev_overrides_community_false_positive(monkeypatch):
    _no_org_memory(monkeypatch)
    monkeypatch.setattr(verdict_memory, "recall_community", lambda sigs, client=None: {"svc:nginx": "false_positive"})
    agent = ValidationAgent()
    f = _finding("3")
    agent.run(_state([f], [EnrichedFinding(finding_id="3", threat_context="", exploitability="active",
                                           public_exploits_exist=True)]))
    assert f.verdict == "confirmed"  # active exploitation beats community noise consensus
