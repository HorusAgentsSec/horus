"""
Tests for the board posture report over email — the monthly PDF digest.

Covers: only opted-in email integrations receive it; the email carries the PDF attachment;
orgs with no posture history are skipped; and send_email actually attaches binary parts.
All backend access is faked, so no Supabase/SMTP is needed.
"""

import smtplib

import pytest

from backend.core import notify


class _Query:
    """Minimal fluent stand-in for a supabase query: every filter returns self; execute()
    yields whatever canned rows the table was seeded with."""

    def __init__(self, rows):
        self._rows = rows
        self._single = False

    def select(self, *a, **k):
        return self

    def eq(self, *a, **k):
        return self

    def gte(self, *a, **k):
        return self

    def order(self, *a, **k):
        return self

    def single(self):
        self._single = True
        return self

    def execute(self):
        data = self._rows[0] if self._single and self._rows else self._rows
        return type("R", (), {"data": data})()


class _FakeSupabase:
    def __init__(self, tables):
        self._tables = tables

    def table(self, name):
        return _Query(list(self._tables.get(name, [])))


def _snapshots(n=10):
    return [
        {
            "snapshot_date": f"2026-05-{d:02d}",
            "risk_score": 40 - d,
            "open_findings": 8,
            "kev_active": 1,
            "critical": 1,
            "high": 2,
            "medium": 2,
            "low": 1,
            "info": 0,
        }
        for d in range(1, n + 1)
    ]


@pytest.fixture
def capture_email(monkeypatch):
    sent = []
    monkeypatch.setattr(
        notify, "send_email",
        lambda config, subject, body, attachments=None: sent.append(
            {"config": config, "subject": subject, "body": body, "attachments": attachments}
        ),
    )
    return sent


def _patch_supabase(monkeypatch, tables):
    monkeypatch.setattr(notify, "supabase", _FakeSupabase(tables))


def test_emails_only_opted_in_integrations(monkeypatch, capture_email):
    _patch_supabase(monkeypatch, {
        "integrations": [
            {"id": "a", "type": "email", "enabled": True, "config": {"to": ["board@co.com"], "posture_report": True}},
            {"id": "b", "type": "email", "enabled": True, "config": {"to": ["ops@co.com"]}},  # not opted in
        ],
        "posture_snapshots": _snapshots(),
        "organizations": [{"name": "Acme Corp"}],
    })

    sent_count = notify.send_posture_report("org-1", days=90)

    assert sent_count == 1
    assert len(capture_email) == 1
    msg = capture_email[0]
    assert msg["config"]["to"] == ["board@co.com"]
    # The PDF is attached.
    assert msg["attachments"] and len(msg["attachments"]) == 1
    filename, data, maintype, subtype = msg["attachments"][0]
    assert filename.endswith(".pdf") and (maintype, subtype) == ("application", "pdf")
    assert data[:5] == b"%PDF-"
    assert "Acme Corp" in msg["subject"]


def test_no_opted_in_integrations_sends_nothing(monkeypatch, capture_email):
    _patch_supabase(monkeypatch, {
        "integrations": [
            {"id": "b", "type": "email", "enabled": True, "config": {"to": ["ops@co.com"]}},
        ],
        "posture_snapshots": _snapshots(),
        "organizations": [{"name": "Acme Corp"}],
    })
    assert notify.send_posture_report("org-1", days=90) == 0
    assert capture_email == []


def test_org_without_history_is_skipped(monkeypatch, capture_email):
    _patch_supabase(monkeypatch, {
        "integrations": [
            {"id": "a", "type": "email", "enabled": True, "config": {"to": ["board@co.com"], "posture_report": True}},
        ],
        "posture_snapshots": [],  # no posture history yet
        "organizations": [{"name": "Acme Corp"}],
    })
    assert notify.send_posture_report("org-1", days=90) == 0
    assert capture_email == []


def test_send_email_attaches_binary(monkeypatch):
    """send_email puts the bytes on the message as a real attachment part."""
    captured = {}

    class _SMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            pass

        def login(self, *a):
            pass

        def send_message(self, msg):
            captured["msg"] = msg

    monkeypatch.setattr(smtplib, "SMTP", _SMTP)

    notify.send_email(
        {"to": ["x@y.com"], "smtp_host": "smtp.test", "use_tls": False},
        "Subject",
        "Body",
        attachments=[("report.pdf", b"%PDF-1.7 fake", "application", "pdf")],
    )

    msg = captured["msg"]
    parts = list(msg.iter_attachments())
    assert len(parts) == 1
    assert parts[0].get_filename() == "report.pdf"
    assert parts[0].get_content_type() == "application/pdf"
    assert parts[0].get_payload(decode=True) == b"%PDF-1.7 fake"
