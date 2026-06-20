"""Tests for the Microsoft Teams notification channel (added 2026-06-20)."""

from backend.core import notify


def test_teams_md_adapts_slack_markup():
    # Slack `*bold*` becomes Teams `**bold**`; lone newlines become blank lines.
    assert notify._teams_md("*hi*") == "**hi**"
    assert notify._teams_md("a\nb") == "a\n\nb"
    assert notify._teams_md("*a*\n*b*") == "**a**\n\n**b**"


def test_send_teams_posts_messagecard(monkeypatch):
    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent["url"] = url
        sent["json"] = json

        class _Resp:
            def raise_for_status(self):
                pass

        return _Resp()

    monkeypatch.setattr(notify.httpx, "post", fake_post)

    summary = {
        "asset": "api.example.com",
        "total": 3,
        "counts": {"critical": 1, "high": 2},
        "kev": ["CVE-2023-1234"],
    }
    notify.send_teams("https://example.webhook.office.com/x", summary)

    assert sent["url"] == "https://example.webhook.office.com/x"
    card = sent["json"]
    assert card["@type"] == "MessageCard"
    assert "api.example.com" in card["title"]
    # Teams bold (**), counts, and the KEV line all present.
    assert "**3 findings**" in card["text"]
    assert "CVE-2023-1234" in card["text"]
