"""
Jobs API — the background-work history.

Read-only view over the `jobs` table: every scheduled scan, discovery run, CVE sync, Watchtower
pass, posture snapshot and board report, with status, duration and a result summary. RLS scopes
rows to the caller's org plus system-wide jobs. This is the operations log behind the "is the
platform actually doing its job" view.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import cancel
from backend.core.audit import log_action

router = APIRouter(prefix="/jobs", tags=["jobs"])

VALID_STATUS = {"running", "completed", "failed", "canceled"}


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


@router.post("/{job_id}/cancel")
async def cancel_job(
    job_id: str,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Stop a running job. Marks the DB row canceled immediately and sets the
    cooperative cancel flag so the worker exits at its next safe checkpoint."""
    row = (
        db.table("jobs")
        .select("id, job_type, ref_id, org_id, status")
        .eq("id", job_id)
        .maybe_single()
        .execute()
        .data
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    # Org isolation — allow if it belongs to the user's org or has no org (system job)
    if row.get("org_id") and row["org_id"] != user["org_id"]:
        raise HTTPException(status_code=403, detail="Cannot cancel another org's job")

    if row["status"] != "running":
        raise HTTPException(status_code=400, detail=f"Job is not running (status: {row['status']})")

    # Mark canceled in DB immediately so the UI updates before the worker notices
    db.table("jobs").update({
        "status": "canceled",
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", job_id).execute()

    # Set cooperative cancel flag — workers poll this between checkpoints
    cancel.request(job_id)

    # For scan jobs: also kill any subprocess and cancel pending/running scans
    if row["job_type"] == "scan_schedule":
        _cancel_running_scans(user["org_id"], db)

    # For adversarial jobs: also mark the linked adversarial_run as canceled
    if row["job_type"] == "adversarial" and row.get("ref_id"):
        db.table("adversarial_runs").update({
            "status": "canceled",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", row["ref_id"]).eq("status", "running").execute()

    log_action(
        user["org_id"], user["id"], "job.canceled",
        entity_type="job", entity_id=job_id,
        metadata={"job_type": row["job_type"]},
    )
    return {"status": "canceled", "job_id": job_id}


def _cancel_running_scans(org_id: str, db: Client) -> None:
    """Kill active scanner subprocesses and mark pending/running scans as canceled."""
    from backend.core.process_registry import cancel_scan_processes

    scans = (
        db.table("scans")
        .select("id")
        .eq("org_id", org_id)
        .in_("status", ["running", "pending"])
        .execute()
        .data or []
    )
    now = datetime.now(timezone.utc).isoformat()
    for scan in scans:
        scan_id = scan["id"]
        cancel_scan_processes(scan_id)
        db.table("scans").update({
            "status": "canceled",
            "completed_at": now,
        }).eq("id", scan_id).execute()
