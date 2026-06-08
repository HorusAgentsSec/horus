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
    """Posture snapshots over the last `days`, oldest first, with current value and trend."""
    return load_timeline(db, user["org_id"], days)


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
