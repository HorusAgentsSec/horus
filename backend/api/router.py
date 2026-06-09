from fastapi import APIRouter, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.core import scheduler
from backend.api import assets, scans, findings, agents, permissions, team, audit, account, onboarding, metrics, integrations, discovery, watchtower, posture, jobs, privacy, adversarial, phishing, hibp

api_router = APIRouter(prefix="/api")

api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(agents.router)
api_router.include_router(permissions.router)
api_router.include_router(team.router)
api_router.include_router(audit.router)
api_router.include_router(account.router)
api_router.include_router(onboarding.router)
api_router.include_router(metrics.router)
api_router.include_router(integrations.router)
api_router.include_router(discovery.router)
api_router.include_router(watchtower.router)
api_router.include_router(posture.router)
api_router.include_router(jobs.router)
api_router.include_router(privacy.router)
api_router.include_router(adversarial.router)
api_router.include_router(phishing.router)
api_router.include_router(hibp.router)


# ── Schedules ──────────────────────────────────────────────────────────────────
from fastapi import APIRouter as _R
from backend.models.schemas import ScheduleCreate, ScheduleUpdate

schedules_router = _R(prefix="/schedules", tags=["schedules"])


@schedules_router.get("")
async def list_schedules(user=Depends(get_current_user), db: Client = Depends(get_db)):
    schedules = (
        db.table("scan_schedules").select("*").eq("org_id", user["org_id"]).execute().data or []
    )
    # Enrich with last_run (from the job history) and next_run (from the live scheduler) so the UI
    # can show "configured once, and here's proof it's running".
    jobs = (
        db.table("jobs")
        .select("ref_id, status, started_at, finished_at, detail")
        .eq("org_id", user["org_id"])
        .eq("job_type", "scan_schedule")
        .order("started_at", desc=True)
        .limit(200)
        .execute()
        .data
        or []
    )
    last_by_ref: dict[str, dict] = {}
    for j in jobs:
        last_by_ref.setdefault(j["ref_id"], j)  # newest-first → first seen per schedule wins
    for s in schedules:
        last = last_by_ref.get(s["id"])
        s["last_run"] = last
        s["next_run"] = scheduler.next_run_for(s["id"])
    return schedules


@schedules_router.post("", status_code=201)
async def create_schedule(
    body: ScheduleCreate, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    row = db.table("scan_schedules").insert(
        {**body.model_dump(), "org_id": user["org_id"]}
    ).execute().data[0]
    # Register the cron job live so it runs without a server restart.
    scheduler.schedule_job(row)
    return row


@schedules_router.patch("/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    rows = (
        db.table("scan_schedules")
        .update(updates)
        .eq("id", schedule_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "schedule not found")
    # Re-register (or remove, if it was just disabled) to reflect the change live.
    scheduler.schedule_job(rows[0])
    return rows[0]


@schedules_router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    db.table("scan_schedules").delete().eq("id", schedule_id).eq(
        "org_id", user["org_id"]
    ).execute()
    scheduler.unschedule_job(schedule_id)


api_router.include_router(schedules_router)


# ── Notifications ──────────────────────────────────────────────────────────────
notifications_router = _R(prefix="/notifications", tags=["notifications"])


@notifications_router.get("")
async def list_notifications(user=Depends(get_current_user), db: Client = Depends(get_db)):
    return (
        db.table("notifications")
        .select("*")
        .eq("user_id", user["id"])
        .eq("read", False)
        .order("created_at", desc=True)
        .execute()
        .data
    )


@notifications_router.patch("/{notification_id}/read", status_code=204)
async def mark_read(
    notification_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    db.table("notifications").update({"read": True}).eq("id", notification_id).eq(
        "user_id", user["id"]
    ).execute()


api_router.include_router(notifications_router)


# ── Dashboard stats ─────────────────────────────────────────────────────────────
dashboard_router = _R(prefix="/dashboard", tags=["dashboard"])


@dashboard_router.get("/stats")
async def dashboard_stats(user=Depends(get_current_user), db: Client = Depends(get_db)):
    org_id = user["org_id"]

    assets_count = len(
        db.table("assets").select("id").eq("org_id", org_id).eq("is_active", True).execute().data
    )

    from backend.core.posture import is_suppressed

    findings_data = (
        db.table("findings").select("severity, raw_data").eq("org_id", org_id).eq("status", "open").execute().data
    )
    by_severity: dict[str, int] = {}
    for f in findings_data:
        # Skip likely false positives so the dashboard counts match the posture score.
        if is_suppressed(f.get("raw_data")):
            continue
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    recent_scans = (
        db.table("scans")
        .select("id, status, created_at, assets(name)")
        .eq("org_id", org_id)
        .order("created_at", desc=True)
        .limit(5)
        .execute()
        .data
    )

    pending_suggestions = len(
        db.table("agent_suggestions")
        .select("id")
        .eq("org_id", org_id)
        .eq("status", "pending")
        .execute()
        .data
    )

    return {
        "total_assets": assets_count,
        "open_findings_by_severity": by_severity,
        "recent_scans": recent_scans,
        "pending_suggestions": pending_suggestions,
    }


api_router.include_router(dashboard_router)
