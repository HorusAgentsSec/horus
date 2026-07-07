"""
Tests for the redaction layer — pseudonymizing prompts before they reach a cloud LLM.

Covers: seeds and structural patterns (host/IP/email/FQDN) are masked; reference domains are kept;
the same value maps to a stable placeholder; redact→restore round-trips; short/common seeds don't
clobber unrelated words; and build_redactor seeds from a ScanState.
"""

from backend.agents.state import AssetInfo, ScanState
from backend.core.redaction import Redactor, build_redactor


def test_seeds_and_patterns_are_masked():
    r = Redactor([("internal-db.corp.example.com", "HOST"), ("Production DB", "NAME")])
    text = ("Production DB at internal-db.corp.example.com (10.0.5.12) "
            "contact admin@corp.example.com about CVE-2021-44228")
    out = r.redact(text)

    assert "internal-db.corp.example.com" not in out
    assert "10.0.5.12" not in out
    assert "admin@corp.example.com" not in out
    assert "Production DB" not in out
    assert "[HOST_1]" in out and "[IP_1]" in out and "[EMAIL_1]" in out
    assert "CVE-2021-44228" in out  # technical content preserved


def test_reference_domains_are_not_redacted():
    r = Redactor()
    out = r.redact("See https://nvd.nist.gov/vuln/detail/CVE-2021-44228 and mitre.org")
    assert "nvd.nist.gov" in out
    assert "mitre.org" in out


def test_stable_placeholders():
    r = Redactor()
    out = r.redact("host evil.attacker.net seen twice: evil.attacker.net")
    # Same value → same placeholder both times.
    assert out.count("[HOST_1]") == 2
    assert "evil.attacker.net" not in out


def test_round_trip_restores():
    r = Redactor([("secret-host.internal", "HOST")])
    original = "Finding on secret-host.internal at 192.168.1.1"
    red = r.redact(original)
    assert r.restore(red) == original


def test_short_seeds_do_not_clobber():
    # A 2-char asset name must not turn "web server" into "[NAME_1] server".
    r = Redactor([("db", "NAME")])
    out = r.redact("the web server and the database")
    assert out == "the web server and the database"


def test_word_boundary_seed():
    # Seed must match as a whole token, not inside another word.
    r = Redactor([("host1.corp.net", "HOST")])
    out = r.redact("host1.corp.net and host1.corp.network")
    assert "[HOST_1] and" in out
    # the longer hostname is a different value → its own placeholder, original gone
    assert "host1.corp.net " not in out.replace("[HOST_1] ", "")


def test_build_redactor_from_state():
    state = ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="Prod Web", host="web.internal.corp", type="domain",
                        is_internal=True, tags=[]),
    )
    r = build_redactor(state)
    out = r.redact("scan of Prod Web on web.internal.corp")
    assert "web.internal.corp" not in out
    assert "Prod Web" not in out


def test_empty_and_none_safe():
    r = Redactor()
    assert r.redact("") == ""
    assert r.restore("") == ""


# ── BaseAgent integration: real names must not leave call_llm ────────────────────

def test_call_llm_redacts_in_flight_and_restores(monkeypatch):
    import types
    from backend.agents import base
    from backend.agents.base import BaseAgent

    captured = {}

    def fake_create(**kwargs):
        captured["user"] = kwargs["messages"][1]["content"]
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(
                content=f"The host {captured['user'].split()[-1]} is vulnerable"))],
            usage=types.SimpleNamespace(prompt_tokens=10, completion_tokens=5),
        )

    monkeypatch.setattr(base._client.chat.completions, "create", fake_create)

    class _Probe(BaseAgent):
        agent_type = "analyst"
        def run(self, state):  # pragma: no cover - not used
            ...

    agent = _Probe()
    agent.redactor = Redactor([("secret-db.internal.corp", "HOST")])
    text, _ = agent.call_llm("system", "analyze host secret-db.internal.corp")

    assert "secret-db.internal.corp" not in captured["user"]   # no leak to the model
    assert "[HOST_1]" in captured["user"]
    assert "secret-db.internal.corp" in text                   # restored on the way back


def test_call_llm_without_redactor_sends_plaintext(monkeypatch):
    import types
    from backend.agents import base
    from backend.agents.base import BaseAgent

    captured = {}
    monkeypatch.setattr(base._client.chat.completions, "create", lambda **k: (
        captured.update(user=k["messages"][1]["content"]) or types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="ok"))],
            usage=types.SimpleNamespace(prompt_tokens=1, completion_tokens=1))))

    class _Probe(BaseAgent):
        agent_type = "analyst"
        def run(self, state): ...

    agent = _Probe()  # no redactor set
    agent.call_llm("system", "host plain.example.com")
    assert captured["user"] == "host plain.example.com"

