from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from backend.api.auth import get_current_user, evict_user_sessions
from backend.api.deps import require_role
from backend.core.audit import log_action
from backend.core.password import generate_temp_password
from backend.core.supabase_client import supabase

router = APIRouter(prefix="/team", tags=["team"])

VALID_ROLES = ("admin", "analyst", "viewer")


class InviteRequest(BaseModel):
    email: EmailStr
    role: str = "analyst"


class RoleUpdate(BaseModel):
    role: str


@router.get("")
async def list_members(user: dict = Depends(get_current_user)):
    profiles = (
        supabase.table("profiles")
        .select("id, role, full_name, created_at")
        .eq("org_id", user["org_id"])
        .is_("deleted_at", "null")
        .order("created_at")
        .execute()
    )

    # Single call to get all auth users, then build a lookup map
    all_auth_users = supabase.auth.admin.list_users()
    email_map = {u.id: u.email for u in all_auth_users}

    members = [
        {**p, "email": email_map.get(p["id"])}
        for p in profiles.data
    ]

    pending = (
        supabase.table("invitations")
        .select("id, email, role, accepted, expires_at, created_at")
        .eq("org_id", user["org_id"])
        .eq("accepted", False)
        .execute()
    )

    return {"members": members, "pending": [{"pending": True, **i} for i in pending.data]}


@router.post("/invite", status_code=201)
async def invite_member(
    body: InviteRequest,
    user: dict = Depends(require_role("admin")),
):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {VALID_ROLES}")

    # Seat enforcement: orgs on a per-seat plan carry settings.seats (synced from Stripe).
    # Orgs without it (manual / enterprise) are unlimited. Block adding past the paid count.
    org = supabase.table("organizations").select("settings").eq("id", user["org_id"]).single().execute().data
    seats = (org.get("settings") or {}).get("seats") if org else None
    if seats is not None:
        active_members = len(
            supabase.table("profiles").select("id").eq("org_id", user["org_id"]).is_("deleted_at", "null").execute().data
        )
        if active_members >= seats:
            raise HTTPException(
                status_code=402,
                detail=f"Seat limit reached ({seats}). Add seats in Settings → Manage billing, then invite.",
            )

    # Check not already a member via email lookup
    all_auth_users = supabase.auth.admin.list_users()
    existing_ids = {
        p["id"] for p in
        supabase.table("profiles").select("id").eq("org_id", user["org_id"]).execute().data
    }
    if any(u.email == body.email and u.id in existing_ids for u in all_auth_users):
        raise HTTPException(status_code=409, detail="User is already a member of this org")

    # Create or reuse auth user
    temp_password = generate_temp_password()
    existing_user = next((u for u in all_auth_users if u.email == body.email), None)
    if existing_user:
        new_user_id = existing_user.id
        temp_password = None  # existing account keeps its own password
    else:
        created = supabase.auth.admin.create_user({
            "email": body.email,
            "password": temp_password,
            "email_confirm": True,
        })
        new_user_id = created.user.id

    supabase.table("profiles").upsert({
        "id": new_user_id,
        "org_id": user["org_id"],
        "role": body.role,
        "full_name": body.email.split("@")[0],
        # New accounts must replace the random temp password on first login.
        # Reused accounts keep their existing password, so no forced change.
        "must_change_password": temp_password is not None,
    }).execute()

    # Membership is the source of truth for belonging (powers the org switcher).
    supabase.table("memberships").upsert(
        {"user_id": new_user_id, "org_id": user["org_id"], "role": body.role, "deleted_at": None},
        on_conflict="user_id,org_id",
    ).execute()

    supabase.table("invitations").upsert({
        "org_id": user["org_id"],
        "email": body.email,
        "role": body.role,
        "invited_by": user["id"],
        "accepted": True,
    }, on_conflict="org_id,email").execute()

    log_action(
        user["org_id"], user["id"], "team.member_invited",
        entity_type="profile", entity_id=new_user_id,
        metadata={"email": body.email, "role": body.role},
    )
    return {"user_id": new_user_id, "email": body.email, "role": body.role, "temp_password": temp_password}


@router.patch("/{user_id}/role")
async def update_role(
    user_id: str,
    body: RoleUpdate,
    user: dict = Depends(require_role("admin")),
):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {VALID_ROLES}")
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    _assert_same_org(user_id, user["org_id"])
    # Source of truth: the member's role in THIS org.
    supabase.table("memberships").update({"role": body.role}).eq("user_id", user_id).eq(
        "org_id", user["org_id"]
    ).execute()
    # Mirror onto the profile only if this org is the member's active one (org_id match),
    # so we never clobber the role they see in a different active org.
    result = supabase.table("profiles").update({"role": body.role}).eq("id", user_id).eq(
        "org_id", user["org_id"]
    ).execute()
    log_action(
        user["org_id"], user["id"], "team.role_changed",
        entity_type="profile", entity_id=user_id,
        metadata={"new_role": body.role},
    )
    return result.data[0]


@router.post("/{user_id}/reset-password")
async def reset_member_password(
    user_id: str,
    user: dict = Depends(require_role("admin")),
):
    # Use /account/change-password for your own password, not this admin path.
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot reset your own password here")
    _assert_same_org(user_id, user["org_id"])

    temp_password = generate_temp_password()
    try:
        supabase.auth.admin.update_user_by_id(user_id, {"password": temp_password})
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to reset password")

    # Force the member to pick a new password on next login.
    supabase.table("profiles").update({"must_change_password": True}).eq("id", user_id).execute()

    # Drop any cached tokens so existing sessions cannot outlive the reset.
    evict_user_sessions(user_id)

    log_action(
        user["org_id"], user["id"], "team.password_reset",
        entity_type="profile", entity_id=user_id,
    )
    return {"user_id": user_id, "temp_password": temp_password}


@router.delete("/{user_id}", status_code=204)
async def remove_member(
    user_id: str,
    user: dict = Depends(require_role("admin")),
):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")
    _assert_same_org(user_id, user["org_id"])
    now = datetime.now(timezone.utc).isoformat()
    # Remove them from THIS org (source of truth).
    supabase.table("memberships").update({"deleted_at": now}).eq("user_id", user_id).eq(
        "org_id", user["org_id"]
    ).execute()
    # ponytail: also soft-delete the profile since team ops here operate on the member's
    # active org. A user whose *active* org is revoked while they still belong elsewhere
    # would need their active org reassigned — out of scope for this iteration.
    supabase.table("profiles").update({"deleted_at": now}).eq("id", user_id).eq(
        "org_id", user["org_id"]
    ).execute()
    log_action(
        user["org_id"], user["id"], "team.member_removed",
        entity_type="profile", entity_id=user_id,
    )


def _assert_same_org(user_id: str, org_id: str):
    r = (
        supabase.table("profiles")
        .select("id").eq("id", user_id).eq("org_id", org_id)
        .execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Member not found in your org")
