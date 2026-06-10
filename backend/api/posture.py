"""
Posture API — the executive risk timeline.

Returns the org's daily posture snapshots (risk_score + severity breakdown) for charting,
plus the current value and the trend versus the start of the window. RLS-scoped reads.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core.posture import load_timeline

router = APIRouter(prefix="/posture", tags=["posture"])


@router.get("/timeline")
async def get_timeline(
    days: int = 90,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Posture snapshots over the last `days`, oldest first, with current value, trend, and
    posture events (annotations) so the frontend can explain score jumps."""
    from datetime import timedelta

    data = load_timeline(db, user["org_id"], days)
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
    events = (
        db.table("posture_events")
        .select("event_date, event_type, description")
        .eq("org_id", user["org_id"])
        .gte("event_date", cutoff)
        .order("event_date")
        .execute()
        .data
        or []
    )
    return {**data, "events": events}


@router.get("/normalized")
async def normalized_metrics(
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Normalized metrics that improve as the team remediates findings, complementing the raw
    risk score which rises with more assets/findings."""
    from datetime import timedelta

    org_id = user["org_id"]

    critical_findings = (
        db.table("findings")
        .select("status, created_at, last_seen_at")
        .eq("org_id", org_id)
        .eq("severity", "critical")
        .execute()
        .data
        or []
    )
    closed_critical = [
        f for f in critical_findings
        if f["status"] in ("resolved", "accepted_risk", "false_positive")
    ]
    # findings has no updated_at; last_seen_at is the closest proxy for "when it was closed"
    # (once remediated, the scanner stops detecting it, so last_seen_at ≈ resolution time).
    fast_closed = [
        f for f in closed_critical
        if f.get("last_seen_at") and f.get("created_at")
        and (
            datetime.fromisoformat(f["last_seen_at"].replace("Z", "+00:00"))
            - datetime.fromisoformat(f["created_at"].replace("Z", "+00:00"))
        ).days <= 7
    ]
    pct_critical_fast = (
        round(len(fast_closed) / len(critical_findings) * 100) if critical_findings else 100
    )

    open_count = len(
        db.table("findings").select("id").eq("org_id", org_id).eq("status", "open").execute().data or []
    )
    asset_count = len(
        db.table("assets").select("id").eq("org_id", org_id).eq("is_active", True).execute().data or []
    )
    findings_per_asset = round(open_count / asset_count, 1) if asset_count else 0

    return {
        "pct_critical_closed_in_7d": pct_critical_fast,
        "open_findings_per_asset": findings_per_asset,
        "total_critical": len(critical_findings),
        "closed_critical": len(closed_critical),
        "fast_closed_critical": len(fast_closed),
    }


@router.get("/report.pdf")
async def get_report_pdf(
    days: int = 90,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Board-ready executive PDF of the posture timeline. RLS-scoped; generated server-side."""
    from backend.core.posture_report import build_posture_pdf

    days = max(1, min(days, 365))
    data = load_timeline(db, user["org_id"], days)

    org = (
        db.table("organizations")
        .select("name")
        .eq("id", user["org_id"])
        .single()
        .execute()
        .data
        or {}
    )

    pdf = build_posture_pdf({"org_name": org.get("name"), "days": days, **data})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"posture-report-{stamp}.pdf"
    return StreamingResponse(
        iter([pdf]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/report/send")
async def send_report_now(
    days: int = 90,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Email the board report PDF now to every email integration opted into board reports.
    Admin-only on-demand trigger (same delivery the monthly cron uses). Returns how many
    integrations it was sent to."""
    from backend.core import notify

    days = max(1, min(days, 365))
    try:
        sent = notify.send_posture_report(user["org_id"], days)
    except Exception as e:
        raise HTTPException(400, f"could not send report: {e}")
    if sent == 0:
        raise HTTPException(
            400,
            "No email integration is opted into board reports yet. Enable 'Monthly board "
            "report' on an email integration first.",
        )
    return {"ok": True, "sent": sent}
