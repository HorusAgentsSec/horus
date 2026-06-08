import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.core import verdict_memory
from backend.models.schemas import FindingStatusUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
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

    result = query.order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
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


def _assert_owned(db: Client, finding_id: str, org_id: str):
    r = db.table("findings").select("id").eq("id", finding_id).eq("org_id", org_id).execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Finding not found")
