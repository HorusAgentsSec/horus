from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core.audit import log_action
from backend.core.executor import submit_scan
from backend.models.schemas import ScanCreate, ScanAllRequest

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("")
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    offset = (page - 1) * per_page
    result = (
        db.table("scans")
        .select("*, assets(name, host)")
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
        .range(offset, offset + per_page - 1)
        .execute()
    )
    return _with_triggered_by_labels(result.data, db, user)


@router.post("", status_code=202)
async def trigger_scan(
    body: ScanCreate,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    asset = (
        db.table("assets")
        .select("id")
        .eq("id", body.asset_id)
        .eq("org_id", user["org_id"])
        .execute()
    )
    if not asset.data:
        raise HTTPException(status_code=404, detail="Asset not found")

    scan = db.table("scans").insert(
        {
            "org_id": user["org_id"],
            "asset_id": body.asset_id,
            "status": "pending",
            "tools_used": body.tools,
            "triggered_by": f"user:{user['id']}",
        }
    ).execute()
    scan_id = scan.data[0]["id"]

    log_action(
        user["org_id"], user["id"], "scan.triggered",
        entity_type="scan", entity_id=scan_id,
        metadata={"asset_id": body.asset_id, "tools": body.tools},
    )

    # Pipeline runs with service-role (it writes findings/suggestions across the org)
    # on a bounded worker pool — excess concurrent scans queue rather than spawn threads.
    submit_scan(scan_id, user["org_id"])

    return {"scan_id": scan_id, "status": "pending"}


@router.post("/scan-all", status_code=202)
async def scan_all_assets(
    body: ScanAllRequest | None = None,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    """Queue a scan for every active asset in the org in one shot."""
    tools = (body or ScanAllRequest()).tools

    assets = (
        db.table("assets")
        .select("id")
        .eq("org_id", user["org_id"])
        .eq("is_active", True)
        .execute()
    )
    asset_ids = [row["id"] for row in (assets.data or [])]
    if not asset_ids:
        return {"queued": 0, "scan_ids": []}

    rows = [
        {
            "org_id": user["org_id"],
            "asset_id": asset_id,
            "status": "pending",
            "tools_used": tools,
            "triggered_by": f"user:{user['id']}",
        }
        for asset_id in asset_ids
    ]
    inserted = db.table("scans").insert(rows).execute()
    scan_ids = [row["id"] for row in (inserted.data or [])]

    # Pipeline runs with service-role on a bounded worker pool — excess concurrent
    # scans queue rather than spawn threads, so a mass enqueue is safe.
    for scan_id in scan_ids:
        submit_scan(scan_id, user["org_id"])

    log_action(
        user["org_id"], user["id"], "scan.scan_all",
        entity_type="scan",
        metadata={"count": len(scan_ids), "tools": tools},
    )
    return {"queued": len(scan_ids), "scan_ids": scan_ids}


@router.post("/cancel-active")
async def cancel_active_scans(
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    active_scans = (
        db.table("scans")
        .select("id")
        .eq("org_id", user["org_id"])
        .in_("status", ["pending", "running"])
        .execute()
    )
    from backend.core.process_registry import cancel_scan_processes
    for row in (active_scans.data or []):
        cancel_scan_processes(row["id"])

    canceled_at = datetime.now(timezone.utc).isoformat()
    result = _mark_scans_canceled(
        db,
        {
            "org_id": user["org_id"],
            "status": ["pending", "running"],
        },
        canceled_at,
    )
    count = len(result.data or [])
    log_action(
        user["org_id"], user["id"], "scan.cancel_active",
        entity_type="scan",
        metadata={"count": count},
    )
    return {"canceled": count}


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    existing = (
        db.table("scans")
        .select("id, status")
        .eq("id", scan_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=404, detail="Scan not found")
    if existing.data["status"] not in ("pending", "running"):
        raise HTTPException(status_code=400, detail="Only pending or running scans can be canceled")

    from backend.core.process_registry import cancel_scan_processes
    cancel_scan_processes(scan_id)

    result = _mark_scans_canceled(
        db,
        {
            "id": scan_id,
            "org_id": user["org_id"],
            "status": ["pending", "running"],
        },
        datetime.now(timezone.utc).isoformat(),
    )
    log_action(
        user["org_id"], user["id"], "scan.canceled",
        entity_type="scan", entity_id=scan_id,
        metadata={"previous_status": existing.data["status"]},
    )
    return result.data[0] if result.data else {"id": scan_id, "status": "canceled"}


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    scan = (
        db.table("scans")
        .select("*, assets(name, host)")
        .eq("id", scan_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not scan.data:
        raise HTTPException(status_code=404, detail="Scan not found")

    agent_runs = (
        db.table("agent_runs")
        .select("*")
        .eq("scan_id", scan_id)
        .order("started_at")
        .execute()
    )
    # Findings stream in as the pipeline persists them (see _stream_findings); the scan detail
    # view polls this endpoint so they appear progressively. Noise is hidden, as in the list view.
    findings = (
        db.table("findings")
        .select("id, title, severity, cvss_score, cve_ids, raw_data")
        .eq("scan_id", scan_id)
        .eq("org_id", user["org_id"])
        .eq("is_noise", False)
        .order("last_seen_at")
        .execute()
    )
    enriched = _with_triggered_by_labels([scan.data], db, user)[0]
    return {**enriched, "agent_runs": agent_runs.data, "findings": findings.data}


def _triggered_by_user_id(scan: dict) -> str | None:
    if scan.get("triggered_by_user_id"):
        return scan["triggered_by_user_id"]
    triggered_by = scan.get("triggered_by")
    if isinstance(triggered_by, str) and triggered_by.startswith("user:"):
        return triggered_by.split(":", 1)[1]
    return None


def _with_triggered_by_labels(scans: list[dict], db: Client, user: dict) -> list[dict]:
    user_ids = {uid for scan in scans if (uid := _triggered_by_user_id(scan))}
    name_map: dict[str, str | None] = {}
    if user_ids:
        profiles = (
            db.table("profiles")
            .select("id, full_name")
            .in_("id", list(user_ids))
            .execute()
        )
        name_map = {p["id"]: p.get("full_name") for p in profiles.data}

    for scan in scans:
        user_id = _triggered_by_user_id(scan)
        if user_id:
            scan["triggered_by_label"] = (
                name_map.get(user_id)
                or (user.get("email") if user_id == user.get("id") else None)
                or "User"
            )
        elif scan.get("triggered_by") == "schedule":
            scan["triggered_by_label"] = "Schedule"
        else:
            scan["triggered_by_label"] = scan.get("triggered_by") or "Unknown"
    return scans


def _mark_scans_canceled(db: Client, filters: dict, canceled_at: str):
    payload = {
        "status": "canceled",
        "completed_at": canceled_at,
        "error_message": "Canceled by user",
    }
    try:
        return _update_scans(db, filters, payload)
    except Exception:
        # Backward compatible with databases that have not applied the migration
        # adding the `canceled` scan status yet.
        return _update_scans(db, filters, {**payload, "status": "failed"})


def _update_scans(db: Client, filters: dict, payload: dict):
    query = db.table("scans").update(payload)
    for column, value in filters.items():
        if isinstance(value, list):
            query = query.in_(column, value)
        else:
            query = query.eq(column, value)
    return query.execute()
