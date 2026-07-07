"""
Tests for the ReporterAgent — focused on robustness to LLM output shape.

Different models format JSON differently; some return a bullet *list* where the ScanReport schema
expects a prose *string* (recommended_next_steps / summary). The agent must coerce, not fail — a
real bug surfaced by the end-to-end run (deepseek returned a list and the whole scan was marked
failed).
"""

from backend.agents.reporter_agent import ReporterAgent, _as_text
from backend.agents.state import AnalyzedFinding, AssetInfo, EnrichedFinding, ScanState


def test_as_text_joins_lists():
    assert _as_text(["a", "b"]) == "- a\n- b"
    assert _as_text("plain") == "plain"
    assert _as_text(None) == ""


def _state():
    return ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="web", host="h", type="domain", is_internal=False, tags=[]),
        analyzed_findings=[
            AnalyzedFinding(id="1", title="XSS", description="d", severity="high",
                            confidence=0.8, rationale="r"),
        ],
        enriched_findings=[
            EnrichedFinding(finding_id="1", threat_context="", exploitability="none",
                            public_exploits_exist=False),
        ],
    )


def test_reporter_coerces_list_fields(monkeypatch):
    agent = ReporterAgent()
    # Simulate a model that returns lists for prose fields.
    monkeypatch.setattr(agent, "call_llm_json", lambda *a, **k: (
        {
            "summary": ["line one", "line two"],
            "recommended_next_steps": ["Patch X", "Rotate creds"],
            "top_priorities": ["1"],
        },
        100,
    ))

    state = agent.run(_state())

    assert state.report is not None
    assert isinstance(state.report.recommended_next_steps, str)
    assert "Patch X" in state.report.recommended_next_steps
    assert isinstance(state.report.summary, str)
    assert "line one" in state.report.summary
    assert state.errors == []  # no validation failure


def test_reporter_handles_string_fields(monkeypatch):
    agent = ReporterAgent()
    monkeypatch.setattr(agent, "call_llm_json", lambda *a, **k: (
        {"summary": "All good", "recommended_next_steps": "Do X", "top_priorities": ["1"]}, 50,
    ))
    state = agent.run(_state())
    assert state.report.summary == "All good"
    assert state.report.recommended_next_steps == "Do X"
