"""
Horus super-admin — cross-org operations gated by the SUPERADMIN_EMAILS allowlist.

This is the manual half of the business model: Horus staff create organizations for
enterprise/Custom customers here. The self-service half (Pro plan) is billing.py.
Both call provision_org().
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from backend.api.deps import require_superadmin
from backend.core.org import OrgNameError
from backend.core.provisioning import ProvisionError, add_member, provision_org
from backend.core.supabase_client import supabase

router = APIRouter(prefix="/admin", tags=["admin"])


class CreateOrgRequest(BaseModel):
    org_name: str
    admin_email: EmailStr
    plan: str = "custom"


class AddMemberRequest(BaseModel):
    email: EmailStr
    role: str = "viewer"


@router.get("/orgs")
async def list_orgs(auth: dict = Depends(require_superadmin)):
    # NOTE: organizations has no deleted_at column (the global soft-delete didn't
    # cover it), so don't filter on it here — profiles does, below.
    orgs = (
        supabase.table("organizations")
        .select("id, name, settings, created_at")
        .order("created_at", desc=True)
        .execute()
        .data
        or []
    )
    profiles = (
        supabase.table("profiles").select("org_id").is_("deleted_at", "null").execute().data or []
    )
    counts: dict[str, int] = {}
    for p in profiles:
        counts[p["org_id"]] = counts.get(p["org_id"], 0) + 1
    for o in orgs:
        o["members"] = counts.get(o["id"], 0)
    return {"orgs": orgs}


@router.post("/orgs", status_code=201)
async def create_org(body: CreateOrgRequest, auth: dict = Depends(require_superadmin)):
    try:
        return provision_org(
            body.org_name, body.admin_email,
            plan=body.plan, source="admin", actor_id=auth["id"],
        )
    except OrgNameError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ProvisionError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.post("/orgs/{org_id}/members", status_code=201)
async def add_org_member(org_id: str, body: AddMemberRequest, auth: dict = Depends(require_superadmin)):
    """Grant an existing (or brand-new) user membership in an org. The multi-org path: this
    is how a user comes to belong to more than one org and can then switch between them."""
    try:
        return add_member(org_id, body.email, body.role, actor_id=auth["id"])
    except ProvisionError as e:
        raise HTTPException(status_code=409, detail=str(e))
