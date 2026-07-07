"""
Tests for the server-side auth gates in backend/api/auth.py: the forced-password-change lock
and the billing-suspended lock are the two mechanisms that block a valid, unexpired JWT from
doing anything except the one exempt action. Both must hold even against a direct API call
(curl/Postman), not just the React UI — that's the whole point of enforcing them server-side.
Also covers API-key resolution, which skips both gates by a different code path.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from backend.api import auth


def _fake_request(path: str) -> SimpleNamespace:
    return SimpleNamespace(url=SimpleNamespace(path=path))


def _fake_creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _mock_gotrue_user(user_id: str, email: str):
    supa = MagicMock()
    supa.auth.get_user.return_value = SimpleNamespace(user=SimpleNamespace(id=user_id, email=email))
    return supa


@pytest.fixture(autouse=True)
def _clear_cache():
    auth._CACHE.clear()
    yield
    auth._CACHE.clear()


async def test_must_change_password_blocks_other_routes():
    supa = _mock_gotrue_user("u1", "a@b.com")
    supa.table.return_value.select.return_value.eq.return_value.is_.return_value.single.return_value.execute.return_value.data = {
        "org_id": "org-1", "role": "admin", "must_change_password": True, "organizations": {"settings": {}},
    }
    with patch.object(auth, "supabase", supa):
        with pytest.raises(HTTPException) as exc:
            await auth.get_current_user(_fake_request("/api/dashboard"), _fake_creds("tok"), None)
    assert exc.value.status_code == 403


async def test_must_change_password_allows_the_change_password_route():
    supa = _mock_gotrue_user("u2", "a@b.com")
    supa.table.return_value.select.return_value.eq.return_value.is_.return_value.single.return_value.execute.return_value.data = {
        "org_id": "org-1", "role": "admin", "must_change_password": True, "organizations": {"settings": {}},
    }
    with patch.object(auth, "supabase", supa):
        user = await auth.get_current_user(
            _fake_request("/api/account/change-password"), _fake_creds("tok"), None
        )
    assert user["must_change_password"] is True
    assert user["org_id"] == "org-1"


async def test_billing_suspended_blocks_other_routes_but_allows_portal():
    old_canceled_at = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    org_settings = {
        "stripe_subscription_id": "sub_1",
        "subscription_status": "canceled",
        "subscription_canceled_at": old_canceled_at,
    }
    supa = _mock_gotrue_user("u3", "a@b.com")
    supa.table.return_value.select.return_value.eq.return_value.is_.return_value.single.return_value.execute.return_value.data = {
        "org_id": "org-1", "role": "admin", "must_change_password": False,
        "organizations": {"settings": org_settings},
    }
    with patch.object(auth, "supabase", supa):
        with pytest.raises(HTTPException) as exc:
            await auth.get_current_user(_fake_request("/api/dashboard"), _fake_creds("tok"), None)
        assert exc.value.status_code == 402

        auth._CACHE.clear()  # re-resolve rather than hit the profile cache from the call above
        user = await auth.get_current_user(_fake_request("/api/billing/portal"), _fake_creds("tok"), None)
    assert user["billing_suspended"] is True


async def test_billing_suspended_false_within_grace_period():
    recent_canceled_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    org_settings = {
        "stripe_subscription_id": "sub_1",
        "subscription_status": "canceled",
        "subscription_canceled_at": recent_canceled_at,
    }
    supa = _mock_gotrue_user("u4", "a@b.com")
    supa.table.return_value.select.return_value.eq.return_value.is_.return_value.single.return_value.execute.return_value.data = {
        "org_id": "org-1", "role": "admin", "must_change_password": False,
        "organizations": {"settings": org_settings},
    }
    with patch.object(auth, "supabase", supa):
        user = await auth.get_current_user(_fake_request("/api/dashboard"), _fake_creds("tok"), None)
    assert user["billing_suspended"] is False


async def test_api_key_resolves_scoped_user_and_skips_password_gate():
    supa = MagicMock()
    supa.table.return_value.select.return_value.eq.return_value.is_.return_value.single.return_value.execute.return_value.data = {
        "id": "key-1", "org_id": "org-9", "role": "viewer",
    }
    with patch.object(auth, "supabase", supa):
        user = await auth.get_current_user(_fake_request("/api/dashboard"), None, "hrs_abc123")

    assert user["is_api_key"] is True
    assert user["org_id"] == "org-9"
    assert user["role"] == "viewer"
    # No profile lookup for the password-change gate — that field simply doesn't exist here.
    assert "must_change_password" not in user


async def test_missing_credentials_raises_401():
    with pytest.raises(HTTPException) as exc:
        await auth.get_current_user(_fake_request("/api/dashboard"), None, None)
    assert exc.value.status_code == 401
