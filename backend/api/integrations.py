"""
Notification integrations API — manage Slack + email targets (admin only).

CRUD is RLS-scoped via the authed client. Secret fields (webhook URLs, SMTP passwords)
are redacted on read so they aren't echoed back to the browser. The /test endpoint runs
server-side with the real config so the admin can verify a target before trusting it —
core to the "configure once and trust it" goal.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import notify
from backend.core.audit import log_action
from backend.models.schemas import IntegrationCreate, IntegrationUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])

VALID_TYPES = {"slack", "email", "pagerduty", "opsgenie"}
_SECRET_KEYS = {"webhook_url", "smtp_password", "integration_key", "api_key"}


def _redact(integration: dict) -> dict:
    """Mask secrets so the config never leaves the server in the clear."""
    config = dict(integration.get("config") or {})
    for key in _SECRET_KEYS:
        if config.get(key):
            config[key] = "••••••••"
    return {**integration, "config": config}


@router.get("")
async def list_integrations(user=Depends(require_role("admin")), db: Client = Depends(get_db)):
    rows = db.table("integrations").select("*").eq("org_id", user["org_id"]).execute().data
    return [_redact(r) for r in rows]


@router.post("", status_code=201)
async def create_integration(
    body: IntegrationCreate, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    if body.type not in VALID_TYPES:
        raise HTTPException(400, f"type must be one of {sorted(VALID_TYPES)}")
    row = (
        db.table("integrations")
        .insert({"org_id": user["org_id"], "type": body.type, "config": body.config, "enabled": body.enabled})
        .execute()
        .data[0]
    )
    log_action(
        user["org_id"], user["id"], "integration.created",
        entity_type="integration", entity_id=row["id"], metadata={"type": body.type},
    )
    return _redact(row)


@router.patch("/{integration_id}")
async def update_integration(
    integration_id: str,
    body: IntegrationUpdate,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "no fields to update")
    rows = (
        db.table("integrations")
        .update(updates)
        .eq("id", integration_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "integration not found")
    log_action(
        user["org_id"], user["id"], "integration.updated",
        entity_type="integration", entity_id=integration_id,
    )
    return _redact(rows[0])


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: str, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    db.table("integrations").delete().eq("id", integration_id).eq("org_id", user["org_id"]).execute()
    log_action(
        user["org_id"], user["id"], "integration.deleted",
        entity_type="integration", entity_id=integration_id,
    )


class BoardReportToggle(BaseModel):
    enabled: bool


@router.patch("/{integration_id}/board-report")
async def set_board_report(
    integration_id: str,
    body: BoardReportToggle,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Opt an email integration in/out of the monthly board posture report. Merges the
    `posture_report` flag into the existing config server-side so SMTP secrets are preserved
    (the redacted config the browser holds can't be safely echoed back)."""
    rows = (
        db.table("integrations")
        .select("*")
        .eq("id", integration_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "integration not found")
    if rows[0]["type"] != "email":
        raise HTTPException(400, "board reports are emailed — enable this on an email integration")

    config = dict(rows[0].get("config") or {})
    config["posture_report"] = body.enabled
    updated = (
        db.table("integrations")
        .update({"config": config})
        .eq("id", integration_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data[0]
    )
    log_action(
        user["org_id"], user["id"], "integration.updated",
        entity_type="integration", entity_id=integration_id,
        metadata={"posture_report": body.enabled},
    )
    return _redact(updated)


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: str, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    """Sends a test message using the real (unredacted) config. Returns ok/error."""
    rows = (
        db.table("integrations")
        .select("*")
        .eq("id", integration_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "integration not found")
    try:
        notify.send_test(rows[0])
    except Exception as e:
        logger.warning("integration test failed for %s: %s", integration_id, e)
        raise HTTPException(400, f"test failed: {e}")
    return {"ok": True}
