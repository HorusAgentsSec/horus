"""
Tests for the privacy-posture derivation (core.privacy) — the honest verdict on where data goes.
"""

import pytest

from backend.core import privacy
from backend.core.config import settings


@pytest.mark.parametrize("url,expected", [
    ("http://localhost:11434/v1", True),
    ("http://127.0.0.1:8000/v1", True),
    ("http://10.0.0.5:11434/v1", True),          # RFC1918
    ("http://192.168.1.10/v1", True),
    ("http://llm.internal/v1", True),
    ("http://ollama.local/v1", True),
    ("https://openrouter.ai/api/v1", False),
    ("https://api.openai.com/v1", False),
    ("", False),
    (None, False),
])
def test_is_local_endpoint(url, expected):
    assert privacy.is_local_endpoint(url) is expected


def _set(monkeypatch, *, llm, redaction, base_url):
    monkeypatch.setattr(settings, "llm_enabled", llm)
    monkeypatch.setattr(settings, "redaction_enabled", redaction)
    monkeypatch.setattr(settings, "llm_base_url", base_url)


def test_mode_no_cloud(monkeypatch):
    _set(monkeypatch, llm=False, redaction=True, base_url="https://openrouter.ai/api/v1")
    s = privacy.privacy_status()
    assert s["mode"] == "no_cloud"
    assert s["data_leaves_perimeter"] is False
    assert s["llm_endpoint"] is None  # not exposed when LLM is off


def test_mode_byo_local(monkeypatch):
    _set(monkeypatch, llm=True, redaction=True, base_url="http://localhost:11434/v1")
    s = privacy.privacy_status()
    assert s["mode"] == "byo_local"
    assert s["data_leaves_perimeter"] is False
    assert s["llm_endpoint"] == "localhost"


def test_mode_cloud_redacted(monkeypatch):
    _set(monkeypatch, llm=True, redaction=True, base_url="https://openrouter.ai/api/v1")
    s = privacy.privacy_status()
    assert s["mode"] == "cloud_redacted"
    assert s["data_leaves_perimeter"] is True


def test_mode_cloud_plain(monkeypatch):
    _set(monkeypatch, llm=True, redaction=False, base_url="https://openrouter.ai/api/v1")
    s = privacy.privacy_status()
    assert s["mode"] == "cloud"
    assert s["data_leaves_perimeter"] is True


def test_status_never_leaks_api_key(monkeypatch):
    _set(monkeypatch, llm=True, redaction=True, base_url="https://openrouter.ai/api/v1")
    s = privacy.privacy_status()
    # Only the host is exposed, and there's no field that could carry the key.
    assert s["llm_endpoint"] == "openrouter.ai"
    assert "api_key" not in s and "llm_api_key" not in s
