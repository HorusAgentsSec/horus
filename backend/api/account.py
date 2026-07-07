"""
Self-service account endpoints for the authenticated user.

change-password backs the forced-password-change flow: an invited user logs in with
the random temp password, the app blocks them until they pick a new one here. The
password update and the flag clear both run with the service-role client so they cannot
be bypassed or partially applied by the user.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.api.auth import get_current_user, evict_user_sessions
from backend.core.audit import log_action
from backend.core.password import PasswordPolicyError, validate_password_strength
from backend.core.supabase_client import supabase

router = APIRouter(prefix="/account", tags=["account"])


class ChangePasswordRequest(BaseModel):
    new_password: str


class ProfileUpdate(BaseModel):
    full_name: str | None = None


@router.get("/profile")
async def get_profile(user: dict = Depends(get_current_user)):
    row = (
        supabase.table("profiles")
        .select("full_name")
        .eq("id", user["id"])
        .single()
        .execute()
    ).data or {}
    # Email and role are shown read-only: email is owned by GoTrue (changing it needs a
    # confirmation flow), and role is assigned by an org admin from the Team page — a user
    # editing their own role would be privilege escalation.
    return {"full_name": row.get("full_name"), "email": user["email"], "role": user["role"]}


@router.put("/profile")
async def update_profile(body: ProfileUpdate, user: dict = Depends(get_current_user)):
    # Whitelist: only full_name is user-editable. Never trust the client for role/org_id.
    if body.full_name is None:
        return await get_profile(user)
    supabase.table("profiles").update(
        {"full_name": body.full_name.strip() or None}
    ).eq("id", user["id"]).execute()
    log_action(
        user["org_id"], user["id"], "account.profile_updated",
        entity_type="profile", entity_id=user["id"],
    )
    return await get_profile(user)


@router.post("/logout-others")
async def logout_others(user: dict = Depends(get_current_user)):
    """Revoke every other session of this user, keeping the current one alive.

    GoTrue's `others` scope invalidates all refresh tokens except the one behind the
    JWT we pass, so the caller stays logged in and every other device is signed out.
    """
    if user.get("is_api_key"):
        raise HTTPException(status_code=400, detail="Not available for API keys")
    try:
        supabase.auth.admin.sign_out(user["token"], "others")
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to revoke other sessions")
    log_action(
        user["org_id"], user["id"], "account.sessions_revoked",
        entity_type="profile", entity_id=user["id"],
    )
    return {"status": "ok"}


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: dict = Depends(get_current_user),
):
    try:
        validate_password_strength(body.new_password)
    except PasswordPolicyError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        supabase.auth.admin.update_user_by_id(user["id"], {"password": body.new_password})
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to update password")

    supabase.table("profiles").update(
        {"must_change_password": False}
    ).eq("id", user["id"]).execute()

    # Evict this user from the backend token cache so other active sessions
    # cannot reuse a cached token that pre-dates the password change.
    evict_user_sessions(user["id"])

    log_action(
        user["org_id"], user["id"], "account.password_changed",
        entity_type="profile", entity_id=user["id"],
    )
    return {"status": "ok"}
