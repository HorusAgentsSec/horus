"""
Multi-org: list the orgs the caller belongs to, and switch the active one.

`memberships` is the source of truth for belonging; `profiles.org_id` mirrors the *active*
org. Switching updates that mirror (service role) after verifying membership. A DB trigger
(see the multi_org migration) is the final guard against pointing a profile at an org the
user isn't a member of — this endpoint's check is the friendly first line, the trigger is
the hard one.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.auth import evict_user_sessions, get_current_user
from backend.core.audit import log_action
from backend.core.supabase_client import supabase  # service-role client (bypasses RLS)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/orgs", tags=["orgs"])


@router.get("")
async def list_orgs(user: dict = Depends(get_current_user)) -> list[dict]:
    """Orgs the current user is a member of, for the org switcher."""
    rows = (
        supabase.table("memberships")
        .select("org_id, role, organizations(name, settings)")
        .eq("user_id", user["id"])
        .is_("deleted_at", "null")
        .execute()
        .data
    ) or []
    out = []
    for r in rows:
        org = r.get("organizations") or {}
        settings = org.get("settings") or {}
        out.append(
            {
                "org_id": r["org_id"],
                "name": org.get("name"),
                "role": r["role"],
                "icon": settings.get("icon"),  # customizable per-org (lucide name or emoji)
                "active": r["org_id"] == user["org_id"],
            }
        )
    return out


@router.post("/{org_id}/switch")
async def switch_org(org_id: str, user: dict = Depends(get_current_user)) -> dict:
    """Set the caller's active org to `org_id`. Requires an active membership."""
    membership = (
        supabase.table("memberships")
        .select("role")
        .eq("user_id", user["id"])
        .eq("org_id", org_id)
        .is_("deleted_at", "null")
        .execute()
        .data
    ) or []
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of that organization",
        )

    # The trigger re-validates and forces role to match the membership, so this write can't
    # cross-org escalate even if this check were wrong.
    supabase.table("profiles").update({"org_id": org_id}).eq("id", user["id"]).execute()
    # The profile lookup is cached (30s TTL); drop it so the next request sees the new org.
    evict_user_sessions(user["id"])

    log_action(
        org_id, user["id"], "org.switched",
        entity_type="organization", entity_id=org_id,
    )
    return {"org_id": org_id, "role": membership[0]["role"]}
