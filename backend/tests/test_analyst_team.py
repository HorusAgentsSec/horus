"""
Tests for the parallel analyst team.

Two layers: the pure `classify_domain` router (keyword routing, precedence TLS > web > network),
and the AnalystAgent fanning findings out to specialists and merging — verifying all domains'
findings survive the merge, tokens are summed across specialists, and a failing specialist doesn't
sink the others.
"""

from backend.agents import analyst_team
from backend.agents.analyst_agent import AnalystAgent
from backend.agents.state import AssetInfo, RawFinding, ScanState


# ── classify_domain ─────────────────────────────────────────────────────────────

def _raw(tool="nmap", template_id=None, name="x"):
    return RawFinding(tool=tool, template_id=template_id, name=name, host="h", severity="info", raw={})


def test_tls_takes_precedence_over_web():
    # "ssl-cert" contains web-ish nothing but TLS keyword; an http TLS finding still routes to TLS.
    assert analyst_team.classify_domain(_raw(name="ssl-cert expired")) == analyst_team.TLS
    assert analyst_team.classify_domain(_raw(template_id="ssl-dh-params", name="https weak DH")) == analyst_team.TLS


def test_web_routing():
    assert analyst_team.classify_domain(_raw(tool="zap", name="Reflected XSS")) == analyst_team.WEB
    assert analyst_team.classify_domain(_raw(tool="nuclei", template_id="http/exposed-panel")) == analyst_team.WEB
    assert analyst_team.classify_domain(_raw(name="http-csrf")) == analyst_team.WEB


def test_network_routing():
    assert analyst_team.classify_domain(_raw(name="open port 445 smb")) == analyst_team.NETWORK
    assert analyst_team.classify_domain(_raw(tool="nmap", name="ssh-auth-methods")) == analyst_team.NETWORK


def test_generic_fallback():
    assert analyst_team.classify_domain(_raw(tool="other", name="mystery thing")) == analyst_team.GENERIC


def test_classify_accepts_dict():
    assert analyst_team.classify_domain({"tool": "zap", "name": "XSS"}) == analyst_team.WEB


# ── AnalystAgent fan-out / merge ────────────────────────────────────────────────

def _state(raws):
    return ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="web", host="h", type="domain", is_internal=False, tags=[]),
        raw_findings=raws,
    )


def _analyzed(title, sev="medium"):
    return {"title": title, "description": "d", "severity": sev, "cvss_score": None,
            "cve_ids": [], "confidence": 0.7, "rationale": "r"}


def test_team_merges_all_domains_and_sums_tokens(monkeypatch):
    raws = [
        _raw(tool="zap", name="XSS"),                 # web
        _raw(name="open port 445 smb"),               # network
        _raw(name="ssl-cert expired"),                # tls
    ]

    # Each specialist returns one finding tagged with its domain + 10 tokens.
    def fake_analyze(self, asset_id, asset_host, domain, findings):
        self.tokens_used = 10
        self.model_used = "fake-model"
        return [_analyzed(f"{domain}-finding")], 10

    monkeypatch.setattr(analyst_team.SpecialistAnalyst, "analyze", fake_analyze)

    agent = AnalystAgent()
    state = agent.run(_state(raws))

    titles = {f.title for f in state.analyzed_findings}
    assert titles == {"web-finding", "network-finding", "tls-finding"}
    assert agent.tokens_used == 30  # summed across the 3 specialists


def test_one_failing_specialist_does_not_sink_others(monkeypatch):
    raws = [_raw(tool="zap", name="XSS"), _raw(name="open port 445 smb")]

    def fake_analyze(self, asset_id, asset_host, domain, findings):
        if domain == analyst_team.NETWORK:
            raise RuntimeError("network specialist boom")
        self.tokens_used = 5
        return [_analyzed(f"{domain}-finding")], 5

    monkeypatch.setattr(analyst_team.SpecialistAnalyst, "analyze", fake_analyze)

    state = AnalystAgent().run(_state(raws))
    titles = {f.title for f in state.analyzed_findings}
    assert titles == {"web-finding"}  # web survived; network failure was contained


def test_single_domain_uses_generalist(monkeypatch):
    # All findings one domain → no team fan-out; the single generalist call is used.
    called = {"team": 0, "single": 0}
    monkeypatch.setattr(analyst_team.SpecialistAnalyst, "analyze",
                        lambda *a, **k: called.__setitem__("team", called["team"] + 1) or ([], 0))

    def fake_single(self, state):
        called["single"] += 1
        return [_analyzed("solo")]

    monkeypatch.setattr(AnalystAgent, "_run_single", fake_single)
    state = AnalystAgent().run(_state([_raw(tool="zap", name="XSS"), _raw(tool="zap", name="CSRF")]))
    assert called["single"] == 1
    assert called["team"] == 0
    assert [f.title for f in state.analyzed_findings] == ["solo"]
