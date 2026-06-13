from fastapi import APIRouter, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.core import scheduler
from backend.api import assets, scans, findings, agents, permissions, team, audit, account, onboarding, metrics, integrations, discovery, watchtower, posture, jobs, privacy, adversarial, phishing, hibp, settings, api_keys, intel, threat_feeds, incidents

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
api_router.include_router(settings.router)
api_router.include_router(api_keys.router)
api_router.include_router(intel.router)
api_router.include_router(threat_feeds.router)
api_router.include_router(incidents.router)


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


@dashboard_router.get("/metrics")
async def dashboard_metrics(user=Depends(get_current_user), db: Client = Depends(get_db)):
    """Actionable security metrics: SSVC breakdown, KEV exposure, coverage, MTTR, trend."""
    from datetime import datetime, timezone, timedelta

    org_id = user["org_id"]
    now = datetime.now(timezone.utc)
    week_ago = (now - timedelta(days=7)).isoformat()
    two_weeks_ago = (now - timedelta(days=14)).isoformat()

    # ── SSVC breakdown (open findings only) ─────────────────────────────────────
    open_findings = (
        db.table("findings")
        .select("id, asset_id, severity, raw_data, created_at")
        .eq("org_id", org_id)
        .eq("status", "open")
        .execute()
        .data
        or []
    )
    ssvc_counts = {"act": 0, "attend": 0, "track_star": 0, "track": 0, "none": 0}
    kev_active = 0
    assets_with_findings: dict[str, dict] = {}
    for f in open_findings:
        rd = f.get("raw_data") or {}
        ssvc = rd.get("ssvc") or {}
        priority = (ssvc.get("priority") or "none").lower().replace("*", "_star")
        ssvc_counts[priority] = ssvc_counts.get(priority, 0) + 1
        if rd.get("exploitability") == "active":
            kev_active += 1
        aid = f.get("asset_id")
        if aid:
            sev = f.get("severity", "low")
            entry = assets_with_findings.setdefault(aid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "act": 0})
            if sev in entry:
                entry[sev] += 1
            if priority == "act":
                entry["act"] += 1

    # ── Asset coverage (% with a completed scan in last 7 days) ─────────────────
    all_assets = (
        db.table("assets").select("id, name").eq("org_id", org_id).eq("is_active", True).execute().data or []
    )
    asset_id_to_name = {a["id"]: a["name"] for a in all_assets}
    recently_scanned = set(
        r["asset_id"]
        for r in (
            db.table("scans")
            .select("asset_id")
            .eq("org_id", org_id)
            .eq("status", "completed")
            .gte("created_at", week_ago)
            .execute()
            .data
            or []
        )
    )
    total_assets = len(all_assets)
    scanned_assets = len(recently_scanned)
    coverage_pct = round(scanned_assets / total_assets * 100) if total_assets else 0

    # ── Findings trend (this week vs previous week) ──────────────────────────────
    new_this_week = len([f for f in (
        db.table("findings")
        .select("id")
        .eq("org_id", org_id)
        .gte("created_at", week_ago)
        .execute()
        .data or []
    )])
    new_prev_week = len([f for f in (
        db.table("findings")
        .select("id")
        .eq("org_id", org_id)
        .gte("created_at", two_weeks_ago)
        .lt("created_at", week_ago)
        .execute()
        .data or []
    )])
    resolved_this_week = len(
        db.table("findings")
        .select("id")
        .eq("org_id", org_id)
        .in_("status", ["resolved", "accepted_risk", "false_positive"])
        .gte("last_seen_at", week_ago)
        .execute()
        .data
        or []
    )

    # ── MTTR for critical findings (days from created_at to last_seen_at) ────────
    closed_critical = (
        db.table("findings")
        .select("created_at, last_seen_at")
        .eq("org_id", org_id)
        .eq("severity", "critical")
        .in_("status", ["resolved", "accepted_risk"])
        .execute()
        .data
        or []
    )
    mttr_days = None
    if closed_critical:
        durations = []
        for f in closed_critical:
            if f.get("created_at") and f.get("last_seen_at"):
                try:
                    d = (
                        datetime.fromisoformat(f["last_seen_at"].replace("Z", "+00:00"))
                        - datetime.fromisoformat(f["created_at"].replace("Z", "+00:00"))
                    ).days
                    if d >= 0:
                        durations.append(d)
                except Exception:
                    pass
        if durations:
            mttr_days = round(sum(durations) / len(durations), 1)

    # ── Top risky assets (by critical+high open findings, max 5) ─────────────────
    top_assets = sorted(
        [
            {
                "id": aid,
                "name": asset_id_to_name.get(aid, aid[:8]),
                "critical": counts["critical"],
                "high": counts["high"],
                "act": counts["act"],
            }
            for aid, counts in assets_with_findings.items()
        ],
        key=lambda x: (x["critical"] * 10 + x["high"] * 5 + x["act"] * 3),
        reverse=True,
    )[:5]

    return {
        "ssvc": ssvc_counts,
        "kev_active": kev_active,
        "asset_coverage": {
            "scanned": scanned_assets,
            "total": total_assets,
            "pct": coverage_pct,
        },
        "findings_trend": {
            "new_this_week": new_this_week,
            "new_prev_week": new_prev_week,
            "resolved_this_week": resolved_this_week,
        },
        "mttr_critical_days": mttr_days,
        "top_risky_assets": top_assets,
        "open_by_severity": {
            "critical": sum(1 for f in open_findings if f.get("severity") == "critical"),
            "high": sum(1 for f in open_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in open_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in open_findings if f.get("severity") == "low"),
        },
    }


api_router.include_router(dashboard_router)
