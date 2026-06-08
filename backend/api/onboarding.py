"""
First-run onboarding — lets a freshly signed-up user create their organization and
become its admin.

For an open-source self-hosted deployment the first person to sign up has a valid
Supabase session but no profile/org yet, so they can't pass the normal
profile-requiring auth. This endpoint bootstraps them: it creates the org and an admin
profile via the service-role client (regular users can't INSERT organizations under RLS).
Subsequent members join by invitation (team.py), not here.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.api.auth import get_authenticated_user
from backend.core.audit import log_action
from backend.core.org import OrgNameError, normalize_org_name
from backend.core.supabase_client import supabase

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


class OnboardingRequest(BaseModel):
    org_name: str


@router.get("/status")
async def onboarding_status(auth: dict = Depends(get_authenticated_user)):
    """Reports whether the authenticated user already has a profile (is onboarded)."""
    profile = supabase.table("profiles").select("id").eq("id", auth["id"]).execute()
    return {"has_profile": bool(profile.data)}


@router.post("", status_code=201)
async def bootstrap(
    body: OnboardingRequest,
    auth: dict = Depends(get_authenticated_user),
):
    try:
        name = normalize_org_name(body.org_name)
    except OrgNameError as e:
        raise HTTPException(status_code=400, detail=str(e))

    existing = supabase.table("profiles").select("id").eq("id", auth["id"]).execute()
    if existing.data:
        raise HTTPException(status_code=409, detail="User already belongs to an organization")

    org = supabase.table("organizations").insert({"name": name}).execute()
    org_id = org.data[0]["id"]

    supabase.table("profiles").insert({
        "id": auth["id"],
        "org_id": org_id,
        "role": "admin",
        "full_name": (auth.get("email") or "").split("@")[0],
        "must_change_password": False,
    }).execute()

    log_action(
        org_id, auth["id"], "org.created",
        entity_type="organization", entity_id=org_id,
        metadata={"name": name},
    )
    return {"org_id": org_id, "role": "admin"}
