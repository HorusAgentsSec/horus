"""
Asset auto-discovery API — manage domain discovery sources and run them.

Discovery is passive (CT logs + DNS) and creates assets, so mutations require analyst+.
A source can be scheduled (cron_expression) or run on demand via /run, which executes in
the background so the request returns immediately — the UI sees results via the source's
last_run_at / last_found_count and the assets list.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import scheduler
from backend.core.discovery import _validate_private_cidr
from backend.models.schemas import DiscoverySourceCreate, DiscoverySourceUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.get("")
async def list_sources(user=Depends(get_current_user), db: Client = Depends(get_db)):
    return db.table("discovery_sources").select("*").eq("org_id", user["org_id"]).execute().data


@router.post("", status_code=201)
async def create_source(
    body: DiscoverySourceCreate, user=Depends(require_role("analyst")), db: Client = Depends(get_db)
):
    if body.kind not in ("domain", "network"):
        raise HTTPException(400, "kind must be 'domain' or 'network'")
    if body.kind == "domain" and not body.domain:
        raise HTTPException(400, "domain is required for domain discovery")
    if body.kind == "network":
        if not body.network_cidr:
            raise HTTPException(400, "network_cidr is required for network discovery")
        try:
            _validate_private_cidr(body.network_cidr)  # reject public/oversized CIDRs early
        except ValueError as e:
            raise HTTPException(400, str(e))
    row = (
        db.table("discovery_sources")
        .insert({**body.model_dump(), "org_id": user["org_id"]})
        .execute()
        .data[0]
    )
    scheduler.discovery_job(row)  # register cron live (no-op if manual-only/disabled)
    return row


@router.patch("/{source_id}")
async def update_source(
    source_id: str,
    body: DiscoverySourceUpdate,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "no fields to update")
    rows = (
        db.table("discovery_sources")
        .update(updates)
        .eq("id", source_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "discovery source not found")
    scheduler.discovery_job(rows[0])
    return rows[0]


@router.delete("/{source_id}", status_code=204)
async def delete_source(
    source_id: str, user=Depends(require_role("analyst")), db: Client = Depends(get_db)
):
    db.table("discovery_sources").update(
        {"deleted_at": datetime.now(timezone.utc).isoformat(), "enabled": False}
    ).eq("id", source_id).eq("org_id", user["org_id"]).execute()
    scheduler.unschedule_discovery(source_id)


@router.post("/{source_id}/run")
async def run_now(
    source_id: str,
    background: BackgroundTasks,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    """Kicks off a discovery pass in the background. Returns immediately."""
    rows = (
        db.table("discovery_sources")
        .select("id")
        .eq("id", source_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "discovery source not found")
    # Route through the scheduler wrapper so the run is recorded in the job history (manual).
    background.add_task(scheduler._run_discovery, source_id, user["org_id"], "manual")
    return {"status": "started"}
