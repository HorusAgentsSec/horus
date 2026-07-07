"""
Tests for the per-agent detail summaries surfaced live in the scan timeline. Focus on the
validation step, whose detail carries the red/blue deliberation (the transparency feature).
"""

from backend.agents.pipeline import _agent_detail
from backend.agents.state import AnalyzedFinding, AssetInfo, EnrichedFinding, ScanState


def _state(findings, enriched=None, **kw):
    return ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="web", host="h", type="domain", is_internal=False, tags=[]),
        analyzed_findings=findings, enriched_findings=enriched or [], **kw,
    )


def _f(fid, verdict=None, debate=None, rationale=None):
    return AnalyzedFinding(id=fid, title=f"f{fid}", description="d", severity="high",
                           confidence=0.7, rationale="r", verdict=verdict,
                           verdict_rationale=rationale, debate=debate)


def test_validation_detail_includes_debates_and_counts():
    findings = [
        _f("1", verdict="false_positive", rationale="version-only",
           debate={"red": "exploitable", "blue": "not reachable"}),
        _f("2", verdict="confirmed"),  # auto-confirmed, no debate
        _f("3", verdict="likely", debate={"red": "plausible", "blue": "maybe stale"}),
    ]
    detail = _agent_detail("validation", _state(findings))

    assert "3 finding(s) judged" in detail["summary"]
    assert "2 debated" in detail["summary"]
    assert "1 likely false positive" in detail["summary"]
    # Only findings with arguments carry red/blue; all judged findings appear.
    assert len(detail["debates"]) == 3
    fp = next(d for d in detail["debates"] if d["verdict"] == "false_positive")
    assert fp["red"] == "exploitable" and fp["blue"] == "not reachable"


def test_threat_intel_detail_counts_kev():
    findings = [_f("1"), _f("2")]
    enriched = [
        EnrichedFinding(finding_id="1", threat_context="", exploitability="active", public_exploits_exist=True),
        EnrichedFinding(finding_id="2", threat_context="", exploitability="none", public_exploits_exist=False),
    ]
    detail = _agent_detail("threat_intel", _state(findings, enriched))
    assert "2 enriched" in detail["summary"]
    assert "1 actively exploited" in detail["summary"]


def test_unknown_agent_returns_empty():
    assert _agent_detail("mystery", _state([])) == {}
