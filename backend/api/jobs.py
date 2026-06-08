"""
Jobs API — the background-work history.

Read-only view over the `jobs` table: every scheduled scan, discovery run, CVE sync, Watchtower
pass, posture snapshot and board report, with status, duration and a result summary. RLS scopes
rows to the caller's org plus system-wide jobs. This is the operations log behind the "is the
platform actually doing its job" view.
"""

from typing import Optional

from fastapi import APIRouter, Depends
from supabase import Client

from backend.api.auth import get_current_user, get_db

router = APIRouter(prefix="/jobs", tags=["jobs"])

VALID_STATUS = {"running", "completed", "failed"}


@router.get("")
async def list_jobs(
    job_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Recent job executions (newest first). Filter by job_type and/or status."""
    limit = max(1, min(limit, 500))
    query = db.table("jobs").select("*")
    if job_type:
        query = query.eq("job_type", job_type)
    if status in VALID_STATUS:
        query = query.eq("status", status)
    return (
        query.order("started_at", desc=True).limit(limit).execute().data or []
    )


@router.get("/stats")
async def job_stats(user=Depends(get_current_user), db: Client = Depends(get_db)):
    """Lightweight health summary over the last 100 jobs: counts by status, and the most recent
    failure — enough for a status badge without pulling the whole history."""
    rows = (
        db.table("jobs")
        .select("status, job_type, started_at, error")
        .order("started_at", desc=True)
        .limit(100)
        .execute()
        .data
        or []
    )
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    last_failure = next((r for r in rows if r["status"] == "failed"), None)
    return {"by_status": by_status, "last_failure": last_failure, "sampled": len(rows)}
