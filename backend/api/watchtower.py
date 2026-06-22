"""
Watchtower API — continuous-exposure alerts and inventory.

Watchtower runs autonomously (daily job): it re-correlates each asset's software inventory
against newly known-exploited CVEs and raises alerts. These endpoints expose the resulting
alert timeline and the persisted inventory, plus an admin trigger for an on-demand pass.
"""

import logging

from fastapi import APIRouter, BackgroundTasks, Depends
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import scheduler

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/watchtower", tags=["watchtower"])


@router.get("/alerts")
async def list_alerts(user=Depends(get_current_user), db: Client = Depends(get_db)):
    """Most recent continuous-exposure alerts for the org (asset name joined)."""
    return (
        db.table("watchtower_alerts")
        .select("*, assets(name)")
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
        .limit(200)
        .execute()
        .data
    )


@router.get("/inventory")
async def list_inventory(user=Depends(get_current_user), db: Client = Depends(get_db)):
    """The persisted software inventory Watchtower monitors (asset name joined)."""
    return (
        db.table("asset_inventory")
        .select("*, assets(name)")
        .eq("org_id", user["org_id"])
        .order("last_seen_at", desc=True)
        .limit(500)
        .execute()
        .data
    )


@router.post("/run")
async def run_now(background: BackgroundTasks, user=Depends(require_role("admin"))):
    """Trigger an on-demand watchtower pass in the background. Returns immediately.
    Idempotent: the (asset, cve) dedup store prevents duplicate alerts. Recorded in the job
    history as a manual run."""
    background.add_task(scheduler._run_watchtower, trigger="manual")
    return {"status": "started"}

from fastapi.responses import StreamingResponse
import json

from fastapi import Query
from backend.api.auth import mint_stream_ticket, consume_stream_ticket
from backend.api.deps import require_role


@router.post("/stream-ticket")
async def stream_ticket(user=Depends(require_role("admin"))):
    """Mint a short-lived single-use ticket so the EventSource (which cannot send an
    Authorization header) authenticates without putting the JWT in the URL."""
    return {"ticket": mint_stream_ticket(user)}


@router.get("/stream")
async def stream_run(ticket: str = Query(...)):
    """Stream an on-demand watchtower pass and return progress.

    Auth is via a single-use stream ticket (see /stream-ticket), not the raw JWT,
    so the credential in the query string cannot be replayed from logs."""
    user = consume_stream_ticket(ticket)
    if user.get("role") != "admin":
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Forbidden")

    def event_generator():
        from backend.core.watchtower import run_watchtower_generator
        for item in run_watchtower_generator():
            if isinstance(item, str):
                yield f"data: {json.dumps({'msg': item})}\n\n"
            else:
                yield f"data: {json.dumps({'done': True, 'result': item})}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/ransomware-check")
async def ransomware_check_now(user=Depends(require_role("admin")), db: Client = Depends(get_db)):
    """Trigger an on-demand ransomware.live check for the org. Returns immediately with results."""
    from backend.core.watchtower import run_ransomware_check

    try:
        result = run_ransomware_check(user["org_id"], db)
        return {**result, "status": "completed"}
    except Exception as e:
        logger.exception("ransomware check failed for org %s", user["org_id"])
        raise HTTPException(500, f"Ransomware check failed: {str(e)}")


@router.get("/ransomware-victims")
async def list_ransomware_victims(user=Depends(get_current_user), db: Client = Depends(get_db)):
    """List all ransomware.live findings for the org, newest first."""
    # Filter by raw_data->>'source' = 'ransomware.live' (using Postgres JSON operators)
    try:
        results = (
            db.table("findings")
            .select("*")
            .eq("org_id", user["org_id"])
            # Use rpc to filter by JSON field, or fetch all and filter in Python
            .order("first_seen_at", desc=True)
            .limit(200)
            .execute()
            .data or []
        )
        # Filter in Python since PostgREST doesn't expose Postgres JSON operators easily
        return [r for r in results if (r.get("raw_data") or {}).get("source") == "ransomware.live"]
    except Exception as e:
        logger.exception("Failed to list ransomware victims for org %s: %s", user["org_id"], e)
        return []
