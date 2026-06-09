import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import jobs, run_events
from backend.core.audit import log_action

router = APIRouter(prefix="/adversarial", tags=["adversarial"])


@router.get("/findings")
async def list_red_findings(
    status: str | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    category: str | None = None,
    page: int = 1,
    per_page: int = 25,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    offset = (page - 1) * per_page
    query = (
        db.table("red_findings")
        .select("*, assets(name, host)")
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
    )
    if status:
        query = query.eq("status", status)
    if severity:
        query = query.eq("severity", severity)
    if asset_id:
        query = query.eq("asset_id", asset_id)
    if category:
        query = query.eq("category", category)
    return query.range(offset, offset + per_page - 1).execute().data


@router.get("/findings/{finding_id}")
async def get_red_finding(
    finding_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    row = (
        db.table("red_findings")
        .select("*, assets(name, host)")
        .eq("id", finding_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not row.data:
        raise HTTPException(status_code=404, detail="Finding not found")
    return row.data


@router.patch("/findings/{finding_id}")
async def update_red_finding(
    finding_id: str,
    body: dict,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    allowed_fields = {"status", "notes"}
    updates = {k: v for k, v in body.items() if k in allowed_fields}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    valid_statuses = {"open", "responded", "accepted", "false_positive"}
    if "status" in updates and updates["status"] not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {valid_statuses}")

    existing = (
        db.table("red_findings")
        .select("id")
        .eq("id", finding_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=404, detail="Finding not found")

    result = (
        db.table("red_findings")
        .update(updates)
        .eq("id", finding_id)
        .execute()
    )
    log_action(
        user["org_id"], user["id"], "adversarial.finding_updated",
        entity_type="red_finding", entity_id=finding_id,
        metadata=updates,
    )
    return result.data[0] if result.data else {"id": finding_id, **updates}


@router.post("/run", status_code=202)
async def run_adversarial(
    background_tasks: BackgroundTasks,
    body: dict | None = None,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Trigger a Red→Blue adversarial cycle. Returns run_id for SSE streaming."""
    org_id = user["org_id"]
    target_org = (body or {}).get("org_id", org_id)
    if target_org != org_id:
        raise HTTPException(status_code=403, detail="Cannot target another org")

    cycle_run_id = str(uuid.uuid4())
    run_events.create_run(cycle_run_id)

    # Persist the run record immediately so history shows it as "running"
    db.table("adversarial_runs").insert({
        "id": cycle_run_id,
        "org_id": org_id,
        "triggered_by": "manual",
        "status": "running",
    }).execute()

    log_action(
        org_id, user["id"], "adversarial.run_triggered",
        entity_type="org", entity_id=org_id,
    )
    background_tasks.add_task(_run_cycle_task, org_id, cycle_run_id)
    return {"status": "queued", "org_id": org_id, "run_id": cycle_run_id}


def _run_cycle_task(org_id: str, cycle_run_id: str | None = None) -> None:
    import logging
    from backend.core.adversarial import run_adversarial_cycle
    from backend.core.supabase_client import supabase as _supabase

    _log = logging.getLogger(__name__)
    failed = False
    result: dict = {"findings_created": 0, "responses_created": 0}

    try:
        def emit(event: dict) -> None:
            run_events.emit(cycle_run_id, event)

        with jobs.job_run(jobs.ADVERSARIAL, org_id=org_id, ref_id=cycle_run_id, trigger="manual") as detail:
            result = run_adversarial_cycle(
                org_id=org_id, run_id=cycle_run_id, emit=emit, job_id=detail.job_id
            )
            detail.update(result)
    except Exception:
        _log.exception("Adversarial cycle failed for org %s", org_id)
        run_events.emit(cycle_run_id, {
            "type": "error", "agent": "system", "message": "Cycle failed unexpectedly",
        })
        failed = True
    finally:
        run_events.finish(cycle_run_id)
        if cycle_run_id:
            try:
                # .neq("status","canceled") prevents overwriting a cancel set by the API
                _supabase.table("adversarial_runs").update({
                    "status": "failed" if failed else "completed",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "findings_created": result.get("findings_created", 0),
                    "responses_created": result.get("responses_created", 0),
                    "events": run_events.get_all_events(cycle_run_id),
                }).eq("id", cycle_run_id).neq("status", "canceled").execute()
            except Exception as e:
                _log.warning("Failed to persist run to DB: %s", e)


@router.get("/runs/{cycle_run_id}/stream")
async def stream_run(
    cycle_run_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """SSE stream for a live or historical adversarial cycle."""

    async def generate():
        # If not in memory, serve from DB (historical replay)
        if not run_events.run_exists(cycle_run_id):
            row = (
                db.table("adversarial_runs")
                .select("events, status")
                .eq("id", cycle_run_id)
                .eq("org_id", user["org_id"])
                .maybe_single()
                .execute()
                .data
            )
            if row and row.get("events"):
                for event in row["events"]:
                    yield f"data: {json.dumps(event)}\n\n"
            yield 'data: {"type":"done"}\n\n'
            return

        # Live streaming
        offset = 0
        while True:
            events, is_done = run_events.get_events(cycle_run_id, after=offset)
            for event in events:
                yield f"data: {json.dumps(event)}\n\n"
                offset += 1
                if event.get("type") == "done":
                    return
            if is_done and not events:
                yield 'data: {"type":"done"}\n\n'
                return
            await asyncio.sleep(0.3)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history")
async def list_runs(
    page: int = 1,
    per_page: int = 15,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """List historical adversarial run records for this org."""
    offset = (page - 1) * per_page
    rows = (
        db.table("adversarial_runs")
        .select("id, status, findings_created, responses_created, started_at, completed_at, triggered_by")
        .eq("org_id", user["org_id"])
        .order("started_at", desc=True)
        .range(offset, offset + per_page - 1)
        .execute()
        .data or []
    )
    return rows


@router.get("/stats")
async def adversarial_stats(
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Summary counts for the adversarial dashboard widget."""
    org_id = user["org_id"]
    rows = (
        db.table("red_findings")
        .select("severity, status, category")
        .eq("org_id", org_id)
        .execute()
        .data or []
    )
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
        by_category[r["category"]] = by_category.get(r["category"], 0) + 1

    return {
        "total": len(rows),
        "by_status": by_status,
        "by_severity": by_severity,
        "by_category": by_category,
    }


# ── adversarial schedules ─────────────────────────────────────────────────────

@router.get("/schedules")
async def list_adversarial_schedules(
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    from backend.core import scheduler as _scheduler
    rows = (
        db.table("adversarial_schedules")
        .select("*")
        .eq("org_id", user["org_id"])
        .order("created_at")
        .execute()
        .data or []
    )
    run_history = (
        db.table("jobs")
        .select("ref_id, status, started_at, detail")
        .eq("org_id", user["org_id"])
        .eq("job_type", "adversarial_schedule")
        .order("started_at", desc=True)
        .limit(200)
        .execute()
        .data or []
    )
    last_by_ref: dict = {}
    for j in run_history:
        last_by_ref.setdefault(j["ref_id"], j)
    for s in rows:
        s["last_run"] = last_by_ref.get(s["id"])
        s["next_run"] = _scheduler.next_run_for(f"adversarial:{s['id']}")
    return rows


@router.post("/schedules", status_code=201)
async def create_adversarial_schedule(
    body: dict,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    from backend.core import scheduler as _scheduler
    name = (body.get("name") or "").strip()
    cron = (body.get("cron_expression") or "").strip()
    if not name or not cron:
        raise HTTPException(status_code=400, detail="name and cron_expression are required")
    row = db.table("adversarial_schedules").insert({
        "org_id": user["org_id"],
        "name": name,
        "cron_expression": cron,
        "enabled": True,
    }).execute().data[0]
    _scheduler.schedule_adversarial_job(row)
    return row


@router.patch("/schedules/{schedule_id}")
async def update_adversarial_schedule(
    schedule_id: str,
    body: dict,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    from backend.core import scheduler as _scheduler
    existing = (
        db.table("adversarial_schedules")
        .select("id")
        .eq("id", schedule_id)
        .eq("org_id", user["org_id"])
        .maybe_single()
        .execute()
        .data
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Schedule not found")
    updates = {k: v for k, v in body.items() if k in ("name", "cron_expression", "enabled")}
    rows = db.table("adversarial_schedules").update(updates).eq("id", schedule_id).execute().data
    _scheduler.schedule_adversarial_job(rows[0])
    return rows[0]


@router.delete("/schedules/{schedule_id}", status_code=204)
async def delete_adversarial_schedule(
    schedule_id: str,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    from backend.core import scheduler as _scheduler
    db.table("adversarial_schedules").delete().eq("id", schedule_id).eq("org_id", user["org_id"]).execute()
    _scheduler.unschedule_job(f"adversarial:{schedule_id}")
