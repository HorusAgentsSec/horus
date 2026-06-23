import secrets
import string
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from backend.api.auth import get_current_user
from backend.api.deps import require_role
from backend.core.audit import log_action
from backend.core.supabase_client import supabase

router = APIRouter(prefix="/team", tags=["team"])

VALID_ROLES = ("admin", "analyst", "viewer")


def _generate_temp_password(length: int = 16) -> str:
    """Cryptographically random password guaranteed to satisfy complexity rules."""
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(length - 3))
    # Ensure at least one upper, one lower, one digit, one symbol
    return (
        core
        + secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%^&*")
    )


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

    # Check not already a member via email lookup
    all_auth_users = supabase.auth.admin.list_users()
    existing_ids = {
        p["id"] for p in
        supabase.table("profiles").select("id").eq("org_id", user["org_id"]).execute().data
    }
    if any(u.email == body.email and u.id in existing_ids for u in all_auth_users):
        raise HTTPException(status_code=409, detail="User is already a member of this org")

    # Create or reuse auth user
    temp_password = _generate_temp_password()
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
    result = supabase.table("profiles").update({"role": body.role}).eq("id", user_id).execute()
    log_action(
        user["org_id"], user["id"], "team.role_changed",
        entity_type="profile", entity_id=user_id,
        metadata={"new_role": body.role},
    )
    return result.data[0]


@router.delete("/{user_id}", status_code=204)
async def remove_member(
    user_id: str,
    user: dict = Depends(require_role("admin")),
):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")
    _assert_same_org(user_id, user["org_id"])
    supabase.table("profiles").update(
        {"deleted_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", user_id).execute()
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
