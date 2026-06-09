import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.core import verdict_memory
from backend.models.schemas import FindingStatusUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@router.get("")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    tool: Optional[str] = None,
    order_by: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    offset = (page - 1) * per_page
    query = db.table("findings").select("*, assets(name, host)").eq("org_id", user["org_id"])
    if severity:
        query = query.eq("severity", severity)
    if status:
        query = query.eq("status", status)
    if asset_id:
        query = query.eq("asset_id", asset_id)
    if cve_id:
        query = query.contains("cve_ids", [cve_id])
    if tool:
        query = query.eq("raw_data->>tool", tool)

    if order_by == "severity":
        query = query.order("severity", desc=False).order("created_at", desc=True)
    else:
        # default and fallback (epss/ssvc are inside jsonb, order by created_at)
        query = query.order("created_at", desc=True)

    result = query.range(offset, offset + per_page - 1).execute()
    return result.data


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    result = (
        db.table("findings")
        .select("*, assets(name, host)")
        .eq("id", finding_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result.data


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    body: FindingStatusUpdate,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    _assert_owned(db, finding_id, user["org_id"])
    result = db.table("findings").update({"status": body.status}).eq("id", finding_id).execute()
    row = result.data[0]

    # Reflection loop: a human judgement on this finding becomes a prior for future scans
    # (false positive → auto-suppress lookalikes; resolved/accepted → trust them). Best-effort.
    verdict = verdict_memory.STATUS_TO_VERDICT.get(body.status)
    if verdict:
        verdict_memory.record_human_verdict(
            user["org_id"], row, verdict, source="status", user_id=user["id"], db=db
        )
    return row


@router.get("/{finding_id}/suggestions")
async def list_suggestions(
    finding_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    _assert_owned(db, finding_id, user["org_id"])
    result = (
        db.table("agent_suggestions")
        .select("*")
        .eq("finding_id", finding_id)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


class BulkAction(BaseModel):
    ids: List[str]
    action: str  # "mark_false_positive" | "accept_risk" | "mark_open" | "mark_resolved"


@router.post("/bulk")
async def bulk_update_findings(
    body: BulkAction,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    ACTION_TO_STATUS = {
        "mark_false_positive": "false_positive",
        "accept_risk": "accepted_risk",
        "mark_open": "open",
        "mark_resolved": "resolved",
    }
    if body.action not in ACTION_TO_STATUS:
        raise HTTPException(400, f"unknown action: {body.action}")
    if not body.ids:
        raise HTTPException(400, "ids must not be empty")

    new_status = ACTION_TO_STATUS[body.action]
    db.table("findings").update({"status": new_status}).in_("id", body.ids).eq("org_id", user["org_id"]).execute()
    return {"updated": len(body.ids)}


def _assert_owned(db: Client, finding_id: str, org_id: str):
    r = db.table("findings").select("id").eq("id", finding_id).eq("org_id", org_id).execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Finding not found")
