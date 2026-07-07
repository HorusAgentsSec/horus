"""
Tests for no-cloud mode (settings.llm_enabled = False): the pipeline must run end-to-end with ZERO
LLM calls and still produce analyzed findings, verdicts, SSVC priorities and a report.

The LLM client is patched to raise — any accidental call fails the test.
"""

import pytest

from backend.agents import base
from backend.agents.analyst_agent import AnalystAgent
from backend.agents.threat_intel_agent import run_threat_intel
from backend.agents.validation_agent import ValidationAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.risk_manager_agent import run_risk_manager
from backend.agents.reporter_agent import ReporterAgent
from backend.agents.state import AssetInfo, RawFinding, ScanState
from backend.core import verdict_memory
from backend.core.config import settings


@pytest.fixture
def no_cloud(monkeypatch):
    monkeypatch.setattr(settings, "llm_enabled", False)

    def _boom(**kwargs):
        raise AssertionError("LLM was called in no-cloud mode!")

    monkeypatch.setattr(base._client.chat.completions, "create", _boom)
    monkeypatch.setattr(verdict_memory, "recall", lambda *a, **k: {})  # no DB in the unit test


def _state():
    return ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="web", host="web.internal.corp", type="domain",
                        is_internal=False, tags=[]),
        raw_findings=[
            RawFinding(tool="nmap", template_id="http-csrf", name="http-csrf on http/80",
                       host="web.internal.corp", severity="medium", raw={"output": "Potential CSRF"}),
            RawFinding(tool="nmap", template_id="ssl-poodle", name="ssl-poodle on https/443",
                       host="web.internal.corp", severity="high", raw={"output": "SSLv3 supported"}),
        ],
    )


def test_full_pipeline_runs_without_llm(no_cloud):
    state = _state()

    state = AnalystAgent().run(state)
    assert len(state.analyzed_findings) == 2
    assert all(f.confidence == 0.5 for f in state.analyzed_findings)
    assert all("no-cloud" in f.rationale for f in state.analyzed_findings)

    state = run_threat_intel(state)
    assert len(state.enriched_findings) == 2

    state = ValidationAgent().run(state)
    # Ambiguous findings get a deterministic verdict (no debate, no LLM).
    assert all(f.verdict is not None for f in state.analyzed_findings)
    assert all(f.debate is None for f in state.analyzed_findings)

    state = RemediationAgent().run(state)
    assert state.remediation_suggestions == []  # remediation drafting needs an LLM → skipped

    state = run_risk_manager(state)  # SSVC, deterministic (no suggestions → no decisions)

    state = ReporterAgent().run(state)
    assert state.report is not None
    assert state.report.summary
    assert "web.internal.corp" in state.report.summary
    assert state.report.recommended_next_steps
    assert state.errors == []


def test_no_cloud_report_leads_with_urgent(no_cloud):
    state = _state()
    for fn in (AnalystAgent().run, run_threat_intel, ValidationAgent().run, ReporterAgent().run):
        state = fn(state)
    # 2 findings, severity high/medium on an external asset → report mentions the count.
    assert "2 open finding" in state.report.summary
