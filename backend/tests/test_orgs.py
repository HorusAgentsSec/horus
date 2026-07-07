"""
Tests for multi-org switching (backend/api/orgs.py).

The security-critical property: you can only switch to an org you're an active member of,
and switching re-points the profile's active org and drops the cached profile so the next
request is scoped to the new org. (A DB trigger is the hard guard; this is the app layer.)
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from backend.api import orgs

USER = {"id": "u1", "org_id": "org-1"}


def _membership_result(supa, rows):
    """Wire the memberships select chain (.select.eq.eq.is_.execute.data) to `rows`."""
    supa.table.return_value.select.return_value.eq.return_value.eq.return_value.is_.return_value.execute.return_value.data = rows


async def test_switch_requires_membership():
    supa = MagicMock()
    _membership_result(supa, [])  # not a member of the target org
    with patch.object(orgs, "supabase", supa):
        with pytest.raises(HTTPException) as exc:
            await orgs.switch_org("org-2", user=USER)
    assert exc.value.status_code == 403


async def test_switch_sets_active_org_and_evicts_cache():
    supa = MagicMock()
    _membership_result(supa, [{"role": "analyst"}])
    with patch.object(orgs, "supabase", supa), \
         patch.object(orgs, "evict_user_sessions") as evict, \
         patch.object(orgs, "log_action"):
        result = await orgs.switch_org("org-2", user=USER)
    assert result == {"org_id": "org-2", "role": "analyst"}
    # Profile re-pointed at the new org, and the cached profile dropped.
    supa.table.return_value.update.assert_any_call({"org_id": "org-2"})
    evict.assert_called_once_with("u1")


async def test_list_orgs_marks_active_and_surfaces_icon():
    supa = MagicMock()
    supa.table.return_value.select.return_value.eq.return_value.is_.return_value.execute.return_value.data = [
        {"org_id": "org-1", "role": "admin", "organizations": {"name": "Acme", "settings": {"icon": "🛡️"}}},
        {"org_id": "org-2", "role": "viewer", "organizations": {"name": "Beta", "settings": {}}},
    ]
    with patch.object(orgs, "supabase", supa):
        result = await orgs.list_orgs(user=USER)
    by_id = {o["org_id"]: o for o in result}
    assert by_id["org-1"]["active"] is True
    assert by_id["org-1"]["name"] == "Acme"
    assert by_id["org-1"]["icon"] == "🛡️"
    assert by_id["org-2"]["active"] is False
    assert by_id["org-2"]["icon"] is None
