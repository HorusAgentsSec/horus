"""HIBP credential exposure API — admin-only."""

import logging
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/hibp", tags=["hibp"])


@router.post("/check", status_code=202)
async def trigger_check(
    background_tasks: BackgroundTasks,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Launch HIBP domain check in background. Returns immediately."""
    from backend.core import hibp

    org = db.table("organizations").select("id, domain").eq("id", user["org_id"]).single().execute().data
    if not org or not org.get("domain"):
        raise HTTPException(400, "No domain configured for this org")
    background_tasks.add_task(hibp.check_org, user["org_id"], org["domain"])
    return {"status": "queued", "domain": org["domain"]}


@router.get("/breaches")
async def list_breaches(
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """All known credential breaches for this org, joined with employee info."""
    rows = (
        db.table("credential_breaches")
        .select("*, employees(full_name, email, department, karma_score)")
        .eq("org_id", user["org_id"])
        .order("breach_date", desc=True)
        .execute()
        .data or []
    )
    return rows


@router.get("/stats")
async def breach_stats(
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Summary stats: N employees affected, N sensitive breaches, avg karma score."""
    breaches = (
        db.table("credential_breaches")
        .select("employee_id, is_sensitive")
        .eq("org_id", user["org_id"])
        .execute()
        .data or []
    )
    employees_affected = len(set(b["employee_id"] for b in breaches))
    sensitive = sum(1 for b in breaches if b.get("is_sensitive"))

    employees = (
        db.table("employees")
        .select("karma_score")
        .eq("org_id", user["org_id"])
        .execute()
        .data or []
    )
    scores = [e["karma_score"] for e in employees if e.get("karma_score") is not None]
    avg_karma = round(sum(scores) / len(scores)) if scores else 100

    return {
        "total_breaches": len(breaches),
        "employees_affected": employees_affected,
        "sensitive_breaches": sensitive,
        "avg_karma_score": avg_karma,
    }
