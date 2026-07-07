"""
Open-core edition gating: the community edition (AGPL core) must block enterprise-only
features (org switching, non-email integrations, Jira) with 402, and unlock them when
edition == "enterprise". This is the money boundary, so it gets a direct test.
"""

import asyncio

import pytest
from fastapi import HTTPException

from backend.api.deps import require_enterprise
from backend.api.integrations import COMMUNITY_TYPES, VALID_TYPES
from backend.core.config import settings


def test_is_enterprise_parsing(monkeypatch):
    monkeypatch.setattr(settings, "edition", "Enterprise")  # case/space-insensitive
    assert settings.is_enterprise
    monkeypatch.setattr(settings, "edition", "community")
    assert not settings.is_enterprise


# Driven with asyncio.run so the check runs without the pytest-asyncio plugin.
def test_require_enterprise_blocks_community(monkeypatch):
    monkeypatch.setattr(settings, "edition", "community")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_enterprise(user={"id": "u1"}))
    assert exc.value.status_code == 402


def test_require_enterprise_allows_enterprise(monkeypatch):
    monkeypatch.setattr(settings, "edition", "enterprise")
    assert asyncio.run(require_enterprise(user={"id": "u1"})) == {"id": "u1"}


def test_community_types_are_email_only():
    assert COMMUNITY_TYPES == {"email"}
    # Every premium connector is out of the community set but still a valid enterprise type.
    for premium in ("slack", "teams", "pagerduty", "opsgenie", "webhook", "jira"):
        assert premium in VALID_TYPES
        assert premium not in COMMUNITY_TYPES
