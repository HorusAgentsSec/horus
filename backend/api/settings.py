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

router = APIRouter(prefix="/settings", tags=["settings"])

MASK = "••••••••"


class SettingsUpdate(BaseModel):
    shodan_api_key: str | None = None
    breach_directory_api_key: str | None = None
    intelx_api_key: str | None = None


def _row(db: Client, org_id: str) -> dict:
    rows = db.table("org_settings").select("*").eq("org_id", org_id).execute().data or []
    return rows[0] if rows else {}


@router.get("")
async def get_settings(user=Depends(require_role("admin")), db: Client = Depends(get_db)):
    row = _row(db, user["org_id"])
    return {
        "shodan_api_key_set": bool(row.get("shodan_api_key")),
        "breach_directory_api_key_set": bool(row.get("breach_directory_api_key")),
        "intelx_api_key_set": bool(row.get("intelx_api_key")),
    }


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
    return {
        "shodan_api_key_set": bool(row.get("shodan_api_key")),
        "breach_directory_api_key_set": bool(row.get("breach_directory_api_key")),
        "intelx_api_key_set": bool(row.get("intelx_api_key")),
    }
