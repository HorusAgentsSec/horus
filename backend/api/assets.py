from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.api.scans import _with_triggered_by_labels
from backend.core.audit import log_action
from backend.core.target_validation import validate_scan_target, TargetValidationError
from backend.models.schemas import AssetCreate, AssetUpdate

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
async def list_assets(user=Depends(get_current_user), db: Client = Depends(get_db)):
    result = db.table("assets").select("*").eq("org_id", user["org_id"]).execute()
    return result.data


@router.get("/{asset_id}")
async def get_asset(asset_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)):
    _assert_asset_owned(db, asset_id, user["org_id"])
    result = db.table("assets").select("*").eq("id", asset_id).eq("org_id", user["org_id"]).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result.data[0]


@router.post("", status_code=201)
async def create_asset(
    body: AssetCreate,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    try:
        validate_scan_target(body.host, body.is_internal)
    except TargetValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = db.table("assets").insert(
        {**body.model_dump(), "org_id": user["org_id"]}
    ).execute()
    asset = result.data[0]
    log_action(
        user["org_id"], user["id"], "asset.created",
        entity_type="asset", entity_id=asset["id"],
        metadata={
            "name": asset.get("name"),
            "host": asset.get("host"),
            "type": asset.get("type"),
            "is_internal": asset.get("is_internal"),
        },
    )
    return asset


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetUpdate,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    asset = _assert_asset_owned(db, asset_id, user["org_id"])
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if "host" in updates:
        try:
            validate_scan_target(
                updates["host"],
                updates.get("is_internal", asset.get("is_internal", False)),
            )
        except TargetValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))
    result = db.table("assets").update(updates).eq("id", asset_id).execute()
    updated_asset = result.data[0]
    log_action(
        user["org_id"], user["id"], "asset.updated",
        entity_type="asset", entity_id=asset_id,
        metadata={
            "changed_fields": sorted(updates.keys()),
            "name": updated_asset.get("name"),
            "host": updated_asset.get("host"),
        },
    )
    return updated_asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    asset = _assert_asset_owned(db, asset_id, user["org_id"])
    db.table("assets").update(
        {"deleted_at": datetime.now(timezone.utc).isoformat(), "is_active": False}
    ).eq("id", asset_id).execute()
    log_action(
        user["org_id"], user["id"], "asset.deleted",
        entity_type="asset", entity_id=asset_id,
        metadata={"name": asset.get("name"), "host": asset.get("host")},
    )


@router.get("/{asset_id}/scans")
async def list_asset_scans(
    asset_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    _assert_asset_owned(db, asset_id, user["org_id"])
    scans = (
        db.table("scans")
        .select("id, status, created_at, started_at, completed_at, triggered_by, triggered_by_user_id")
        .eq("asset_id", asset_id)
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
        .limit(20)
        .execute()
        .data or []
    )
    # `triggered_by_label` is derived in Python from triggered_by/triggered_by_user_id;
    # it is not a real column (selecting it directly returns a 42703 error).
    return _with_triggered_by_labels(scans, db, user)


@router.get("/{asset_id}/findings/summary")
async def asset_findings_summary(
    asset_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    _assert_asset_owned(db, asset_id, user["org_id"])
    rows = (
        db.table("findings")
        .select("severity, status")
        .eq("asset_id", asset_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data or []
    )
    open_by_sev: dict[str, int] = {}
    for r in rows:
        if r["status"] == "open":
            open_by_sev[r["severity"]] = open_by_sev.get(r["severity"], 0) + 1
    return {"open_by_severity": open_by_sev, "total": len(rows)}


@router.get("/{asset_id}/inventory")
async def asset_inventory(
    asset_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    _assert_asset_owned(db, asset_id, user["org_id"])
    rows = (
        db.table("asset_inventory")
        .select("product, version, port, service_name, last_seen_at")
        .eq("asset_id", asset_id)
        .order("last_seen_at", desc=True)
        .execute()
        .data or []
    )
    return rows


def _assert_asset_owned(db: Client, asset_id: str, org_id: str) -> dict:
    r = db.table("assets").select("id, name, host, is_internal").eq("id", asset_id).eq("org_id", org_id).execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Asset not found")
    return r.data[0]
