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
