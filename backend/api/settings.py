"""
Org settings API — per-organization config the user manages from the Settings page
(as opposed to deploy-time backend env vars). Currently just the Shodan API key.

The secret is never echoed back to the browser: GET returns only whether a key is set,
and PUT only overwrites it when a real (non-blank, non-masked) value is sent. Admin only.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_db
from backend.api.deps import require_role
from backend.core.audit import log_action
from backend.core.supabase_client import supabase as _admin

router = APIRouter(prefix="/settings", tags=["settings"])

MASK = "••••••••"


class SettingsUpdate(BaseModel):
    shodan_api_key: str | None = None
    breach_directory_api_key: str | None = None
    intelx_api_key: str | None = None
    iris_triage_interval_minutes: int | None = None
    token_limit_daily: int | None = None
    token_limit_weekly: int | None = None
    token_limit_monthly: int | None = None


def _row(db: Client, org_id: str) -> dict:
    rows = db.table("org_settings").select("*").eq("org_id", org_id).execute().data or []
    return rows[0] if rows else {}


@router.get("")
async def get_settings(user=Depends(require_role("admin")), db: Client = Depends(get_db)):
    return _settings_response(_row(db, user["org_id"]))


@router.put("")
async def update_settings(
    body: SettingsUpdate,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    updates: dict = {}

    # Only touch the key when the client sends a real value. A blank string clears it;
    # the mask placeholder means "unchanged" (the browser never holds the real secret).
    if body.shodan_api_key is not None and body.shodan_api_key != MASK:
        updates["shodan_api_key"] = body.shodan_api_key.strip() or None

    if body.breach_directory_api_key is not None and body.breach_directory_api_key != MASK:
        updates["breach_directory_api_key"] = body.breach_directory_api_key.strip() or None

    if body.intelx_api_key is not None and body.intelx_api_key != MASK:
        updates["intelx_api_key"] = body.intelx_api_key.strip() or None

    if body.iris_triage_interval_minutes is not None:
        updates["iris_triage_interval_minutes"] = max(5, min(1440, body.iris_triage_interval_minutes))

    # Token limits: None = no limit (cleared), 0 = clear limit
    for period in ("daily", "weekly", "monthly"):
        val = getattr(body, f"token_limit_{period}")
        if val is not None:
            updates[f"token_limit_{period}"] = val if val > 0 else None

    if updates:
        db.table("org_settings").upsert(
            {"org_id": org_id, **updates}, on_conflict="org_id"
        ).execute()
        log_action(
            org_id, user["id"], "settings.updated",
            entity_type="org_settings", entity_id=org_id,
            metadata={"changed_fields": sorted(updates.keys())},
        )

    row = _row(db, org_id)
    return _settings_response(row)


def _settings_response(row: dict) -> dict:
    return {
        "shodan_api_key_set": bool(row.get("shodan_api_key")),
        "breach_directory_api_key_set": bool(row.get("breach_directory_api_key")),
        "intelx_api_key_set": bool(row.get("intelx_api_key")),
        "iris_triage_interval_minutes": row.get("iris_triage_interval_minutes") or 60,
        "token_limit_daily": row.get("token_limit_daily"),
        "token_limit_weekly": row.get("token_limit_weekly"),
        "token_limit_monthly": row.get("token_limit_monthly"),
    }


@router.delete("/organization", status_code=204)
async def delete_organization(
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """
    Permanently delete the organization and all its data (GDPR right to erasure).
    Deletes all auth users in the org, then cascades from organizations table.
    This action is irreversible.
    """
    org_id = user["org_id"]

    # 1. Collect all member user IDs before deleting profiles
    profiles = _admin.table("profiles").select("id").eq("org_id", org_id).execute().data or []

    # 2. Delete the org row — FK CASCADE handles all org-scoped data
    _admin.table("organizations").delete().eq("id", org_id).execute()

    # 3. Delete auth users (profile rows already gone via cascade)
    for p in profiles:
        try:
            _admin.auth.admin.delete_user(p["id"])
        except Exception:
            pass  # user may not exist in auth; cascade already removed the profile

    log_action(
        org_id, user["id"], "org.deleted",
        entity_type="organization", entity_id=org_id,
        metadata={"deleted_by": user.get("email")},
    )
