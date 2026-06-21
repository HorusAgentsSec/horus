"""
Cloud security audit API (AWS).

Credentials live in the `integrations` table (type = 'aws'), managed through the existing
/integrations CRUD. This router only triggers an audit and reports its history. The audit runs in
the background and records a job, exactly like discovery; results land in the normal findings list
hung off the account's "cloud" asset.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from supabase import Client

from backend.api.auth import get_db
from backend.api.deps import require_role
from backend.core import jobs

router = APIRouter(prefix="/cloud", tags=["cloud"])


def _run_audit_job(org_id: str, integration_id: str, trigger: str = "manual") -> None:
    """Background entry point: run the audit inside a job record for history."""
    from backend.core.cloud.aws_audit import run_aws_audit

    try:
        with jobs.job_run(jobs.CLOUD_AUDIT, org_id=org_id, ref_id=integration_id, trigger=trigger) as d:
            d.update(run_aws_audit(org_id, integration_id))
    except Exception as e:  # logged by job_run; keep the worker alive
        import logging
        logging.getLogger(__name__).error("Cloud audit %s failed: %s", integration_id, e)


@router.post("/aws/{integration_id}/audit")
async def run_aws_audit_now(
    integration_id: str,
    background: BackgroundTasks,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Kick off an AWS audit in the background. Admin only (it uses cloud credentials)."""
    row = (
        db.table("integrations")
        .select("id, type")
        .eq("id", integration_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not row.data or row.data.get("type") != "aws":
        raise HTTPException(404, "AWS integration not found")
    background.add_task(_run_audit_job, user["org_id"], integration_id, "manual")
    return {"status": "started"}


@router.get("/audits")
async def list_audits(user=Depends(require_role("analyst")), db: Client = Depends(get_db)):
    """Recent cloud-audit job runs for this org (status, duration, summary)."""
    rows = (
        db.table("jobs")
        .select("*")
        .eq("org_id", user["org_id"])
        .eq("job_type", jobs.CLOUD_AUDIT)
        .order("started_at", desc=True)
        .limit(20)
        .execute()
        .data
    )
    return rows
