from fastapi import APIRouter, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core.audit import log_action
from backend.models.schemas import PermissionPolicyCreate, PermissionPolicyUpdate

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.get("")
async def list_policies(user=Depends(get_current_user), db: Client = Depends(get_db)):
    result = (
        db.table("permission_policies")
        .select("*")
        .eq("org_id", user["org_id"])
        .order("created_at")
        .execute()
    )
    return result.data


@router.post("", status_code=201)
async def create_policy(
    body: PermissionPolicyCreate,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    result = db.table("permission_policies").insert(
        {**body.model_dump(), "org_id": user["org_id"]}
    ).execute()
    policy = result.data[0]
    log_action(
        user["org_id"], user["id"], "permission_policy.created",
        entity_type="permission_policy", entity_id=policy["id"],
        metadata=body.model_dump(),
    )
    return policy


@router.patch("/{policy_id}")
async def update_policy(
    policy_id: str,
    body: PermissionPolicyUpdate,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    _assert_owned(db, policy_id, user["org_id"])
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    result = db.table("permission_policies").update(updates).eq("id", policy_id).execute()
    log_action(
        user["org_id"], user["id"], "permission_policy.updated",
        entity_type="permission_policy", entity_id=policy_id,
        metadata={"changes": updates},
    )
    return result.data[0]


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    _assert_owned(db, policy_id, user["org_id"])
    db.table("permission_policies").delete().eq("id", policy_id).execute()
    log_action(
        user["org_id"], user["id"], "permission_policy.deleted",
        entity_type="permission_policy", entity_id=policy_id,
    )


def _assert_owned(db: Client, policy_id: str, org_id: str):
    r = db.table("permission_policies").select("id").eq("id", policy_id).eq("org_id", org_id).execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Policy not found")
