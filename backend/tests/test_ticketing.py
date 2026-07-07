"""
Tests for Jira ticketing (core/ticketing.py) and the outgoing webhook channel (core/notify.py).

No real Jira/HTTP: httpx is monkeypatched. What matters is that the issue payload carries the
finding's substance, that every failure mode maps to an actionable JiraError (no raw
tracebacks for the user), and that webhook bodies are correctly HMAC-signed.
"""

import hashlib
import hmac
import json

import httpx
import pytest

from backend.core import notify, ticketing


FINDING = {
    "id": "f-1",
    "title": "SQL injection on /login",
    "description": "Boolean-based blind SQLi in the username parameter.",
    "severity": "critical",
    "cvss_score": 9.8,
    "cve_ids": ["CVE-2026-0001"],
    "first_seen_at": "2026-06-10T08:00:00+00:00",
    "raw_data": {"matched_at": "https://app.acme.com/login", "evidence": "payload: ' OR 1=1--"},
    "assets": {"name": "app", "host": "app.acme.com"},
}

CONFIG = {
    "base_url": "https://acme.atlassian.net/",
    "user_email": "bot@acme.com",
    "api_token": "tok",
    "project_key": "SEC",
}


def _adf_text(payload: dict) -> str:
    """Flatten every text node in the ADF description for assertions."""
    out = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text":
                out.append(node.get("text", ""))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload["fields"]["description"])
    return "\n".join(out)


# ── Payload construction ──────────────────────────────────────────────────────

def test_build_issue_payload_carries_finding_substance():
    payload = ticketing.build_issue_payload(FINDING, "SEC")
    fields = payload["fields"]

    assert fields["project"] == {"key": "SEC"}
    assert fields["summary"] == "[Horus][CRITICAL] SQL injection on /login"
    assert "severity-critical" in fields["labels"]

    text = _adf_text(payload)
    assert "app (app.acme.com)" in text
    assert "CVE-2026-0001" in text
    assert "CVSS: 9.8" in text
    assert "Boolean-based blind SQLi" in text
    assert "' OR 1=1--" in text  # evidence from raw_data


def test_build_issue_payload_truncates_huge_evidence_and_summary():
    finding = {
        **FINDING,
        "title": "x" * 500,
        "raw_data": {"evidence": "A" * 10_000},
    }
    payload = ticketing.build_issue_payload(finding, "SEC")
    assert len(payload["fields"]["summary"]) <= 254
    text = _adf_text(payload)
    assert "(truncated)" in text
    assert len(text) < 7000


def test_build_issue_payload_minimal_finding():
    payload = ticketing.build_issue_payload({"title": "t", "severity": "low"}, "SEC")
    assert payload["fields"]["summary"] == "[Horus][LOW] t"
    assert "unknown asset" in _adf_text(payload)


# ── Config validation ────────────────────────────────────────────────────────

def test_validate_config_lists_missing_fields():
    with pytest.raises(ticketing.JiraError) as e:
        ticketing.validate_config({"base_url": "https://x.atlassian.net"})
    msg = str(e.value)
    for key in ("user_email", "api_token", "project_key"):
        assert key in msg


# ── HTTP flow (mocked) ───────────────────────────────────────────────────────

@pytest.fixture
def jira_http(monkeypatch):
    """Monkeypatch httpx.request inside ticketing; the test sets `responder`."""
    calls = []
    state = {"responder": lambda method, url, **kw: httpx.Response(200, json={})}

    def fake_request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        return state["responder"](method, url, **kwargs)

    monkeypatch.setattr(ticketing.httpx, "request", fake_request)
    state["calls"] = calls
    return state


def test_create_issue_happy_path(jira_http):
    jira_http["responder"] = lambda m, u, **kw: httpx.Response(201, json={"key": "SEC-42"})

    ticket = ticketing.create_issue(CONFIG, FINDING)

    assert ticket == {
        "ticket_key": "SEC-42",
        "ticket_url": "https://acme.atlassian.net/browse/SEC-42",
    }
    call = jira_http["calls"][0]
    assert call["method"] == "POST"
    assert call["url"] == "https://acme.atlassian.net/rest/api/3/issue"
    assert call["auth"] == ("bot@acme.com", "tok")
    assert call["json"]["fields"]["project"]["key"] == "SEC"


def test_test_connection_returns_account(jira_http):
    jira_http["responder"] = lambda m, u, **kw: httpx.Response(200, json={"displayName": "Horus Bot"})
    assert ticketing.test_connection(CONFIG) == {"ok": True, "account": "Horus Bot"}
    assert jira_http["calls"][0]["url"] == "https://acme.atlassian.net/rest/api/3/myself"


def test_bad_credentials_maps_to_actionable_error(jira_http):
    jira_http["responder"] = lambda m, u, **kw: httpx.Response(401, json={})
    with pytest.raises(ticketing.JiraError, match="credentials"):
        ticketing.test_connection(CONFIG)


def test_unreachable_host_maps_to_actionable_error(monkeypatch):
    def boom(*a, **kw):
        raise httpx.ConnectError("dns fail")

    monkeypatch.setattr(ticketing.httpx, "request", boom)
    with pytest.raises(ticketing.JiraError, match="could not reach Jira"):
        ticketing.test_connection(CONFIG)


def test_jira_validation_error_surfaces_jira_message(jira_http):
    jira_http["responder"] = lambda m, u, **kw: httpx.Response(
        400, json={"errors": {"project": "valid project is required"}}
    )
    with pytest.raises(ticketing.JiraError, match="valid project is required"):
        ticketing.create_issue(CONFIG, FINDING)


def test_create_issue_without_config_never_calls_http(jira_http):
    with pytest.raises(ticketing.JiraError):
        ticketing.create_issue({}, FINDING)
    assert jira_http["calls"] == []


# ── Outgoing webhook (HMAC signature) ────────────────────────────────────────

def test_webhook_post_signs_body_with_hmac_sha256(monkeypatch):
    captured = {}

    def fake_post(url, content=None, headers=None, timeout=None):
        captured.update(url=url, content=content, headers=headers)
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(notify.httpx, "post", fake_post)

    notify._webhook_post(
        "https://hooks.acme.com/horus", "s3cret", "finding.critical.new",
        {"scan_id": "s-1", "findings": [{"id": "f-1"}]},
    )

    assert captured["url"] == "https://hooks.acme.com/horus"
    assert captured["headers"]["X-Horus-Event"] == "finding.critical.new"

    expected = hmac.new(b"s3cret", captured["content"], hashlib.sha256).hexdigest()
    assert captured["headers"]["X-Horus-Signature"] == f"sha256={expected}"

    body = json.loads(captured["content"])
    assert body["event"] == "finding.critical.new"
    assert body["data"]["findings"] == [{"id": "f-1"}]


def test_webhook_post_without_secret_sends_no_signature(monkeypatch):
    captured = {}

    def fake_post(url, content=None, headers=None, timeout=None):
        captured.update(headers=headers)
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(notify.httpx, "post", fake_post)
    notify._webhook_post("https://hooks.acme.com/horus", "", "test", {})
    assert "X-Horus-Signature" not in captured["headers"]


def test_webhook_post_raises_on_receiver_error(monkeypatch):
    monkeypatch.setattr(
        notify.httpx, "post",
        lambda *a, **kw: httpx.Response(500, request=httpx.Request("POST", "https://x")),
    )
    with pytest.raises(httpx.HTTPStatusError):
        notify._webhook_post("https://hooks.acme.com/horus", "s", "test", {})


def test_send_test_webhook_requires_url():
    with pytest.raises(ValueError, match="url"):
        notify.send_test({"type": "webhook", "config": {}})


def test_send_test_jira_delegates_to_connection_test(monkeypatch):
    monkeypatch.setattr(
        ticketing.httpx, "request",
        lambda m, u, **kw: httpx.Response(200, json={"displayName": "ok"}),
    )
    notify.send_test({"type": "jira", "config": CONFIG})  # must not raise
