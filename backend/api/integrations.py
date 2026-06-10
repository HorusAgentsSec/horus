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
from backend.core import notify, ticketing
from backend.core.audit import log_action
from backend.models.schemas import IntegrationCreate, IntegrationUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])

VALID_TYPES = {"slack", "email", "pagerduty", "opsgenie", "webhook", "jira"}
_SECRET_KEYS = {"webhook_url", "smtp_password", "integration_key", "api_key", "api_token", "secret"}


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


# ── Jira ticketing ────────────────────────────────────────────────────────────
# Registered before the /{integration_id}/* routes so "/jira/…" isn't swallowed by the
# path parameter. Config lives in the integrations table (type="jira"), managed with the
# generic CRUD above; these routes add connection testing and finding → issue creation.


class JiraTicketCreate(BaseModel):
    finding_id: str

    def model_post_init(self, __context):
        import uuid as _uuid
        try:
            _uuid.UUID(self.finding_id)
        except (ValueError, AttributeError):
            from fastapi import HTTPException as _H
            raise _H(400, "finding_id must be a valid UUID")


def _jira_integration(db: Client, org_id: str) -> dict | None:
    rows = (
        db.table("integrations")
        .select("*")
        .eq("org_id", org_id)
        .eq("type", "jira")
        .limit(1)
        .execute()
        .data
    )
    return rows[0] if rows else None


@router.get("/jira/status")
async def jira_status(user=Depends(get_current_user), db: Client = Depends(get_db)):
    """Lightweight, secret-free status for any authed user (the finding page needs to know
    whether to enable the 'Create Jira ticket' button; listing integrations is admin-only)."""
    integ = _jira_integration(db, user["org_id"])
    config = (integ or {}).get("config") or {}
    return {
        "configured": bool(integ) and all(config.get(k) for k in ticketing.REQUIRED_KEYS),
        "enabled": bool(integ and integ.get("enabled")),
        "project_key": config.get("project_key"),
    }


@router.post("/jira/test")
async def jira_test_connection(user=Depends(require_role("admin")), db: Client = Depends(get_db)):
    """Calls Jira's GET /myself with the stored credentials. Returns ok + account, or a 400
    whose detail says exactly what to fix (bad URL, bad token, no access)."""
    integ = _jira_integration(db, user["org_id"])
    if not integ:
        raise HTTPException(400, "Jira is not configured — add the Jira integration first")
    try:
        return ticketing.test_connection(integ.get("config") or {})
    except ticketing.JiraError as e:
        raise HTTPException(400, str(e))


@router.post("/jira/tickets", status_code=201)
async def create_jira_ticket(
    body: JiraTicketCreate, user=Depends(require_role("analyst")), db: Client = Depends(get_db)
):
    """Create a Jira issue from a finding. Idempotent: if the finding already has a jira
    ticket, the existing reference is returned (created=False) instead of duplicating."""
    org_id = user["org_id"]
    existing = (
        db.table("finding_tickets")
        .select("*")
        .eq("org_id", org_id)
        .eq("finding_id", body.finding_id)
        .eq("provider", "jira")
        .execute()
        .data
    )
    if existing:
        return {**existing[0], "created": False}

    integ = _jira_integration(db, org_id)
    if not integ:
        raise HTTPException(400, "Jira is not configured — an admin must add it in Integrations")
    if not integ.get("enabled"):
        raise HTTPException(400, "the Jira integration is disabled — enable it in Integrations")

    findings = (
        db.table("findings")
        .select("*, assets(name, host)")
        .eq("id", body.finding_id)
        .eq("org_id", org_id)
        .execute()
        .data
    )
    if not findings:
        raise HTTPException(404, "finding not found")

    try:
        ticket = ticketing.create_issue(integ.get("config") or {}, findings[0])
    except ticketing.JiraError as e:
        raise HTTPException(502, f"could not create the Jira issue: {e}")

    try:
        row = (
            db.table("finding_tickets")
            .insert(
                {
                    "org_id": org_id,
                    "finding_id": body.finding_id,
                    "provider": "jira",
                    "ticket_key": ticket["ticket_key"],
                    "ticket_url": ticket["ticket_url"],
                    "created_by": user["id"],
                }
            )
            .execute()
            .data[0]
        )
    except Exception:
        # Unique(finding_id, provider) race: someone created it concurrently — return theirs.
        logger.warning("finding_tickets insert conflict for finding %s", body.finding_id)
        rows = (
            db.table("finding_tickets")
            .select("*")
            .eq("org_id", org_id)
            .eq("finding_id", body.finding_id)
            .eq("provider", "jira")
            .execute()
            .data
        )
        if not rows:
            raise HTTPException(
                502,
                f"Jira issue {ticket['ticket_key']} was created but saving the reference failed — "
                "check the issue in Jira before retrying",
            )
        return {**rows[0], "created": False}

    log_action(
        org_id, user["id"], "ticket.created",
        entity_type="finding", entity_id=body.finding_id,
        metadata={"provider": "jira", "ticket_key": ticket["ticket_key"]},
    )
    return {**row, "created": True}


@router.get("/jira/tickets")
async def get_jira_tickets(
    finding_id: str, user=Depends(get_current_user), db: Client = Depends(get_db)
):
    return (
        db.table("finding_tickets")
        .select("*")
        .eq("org_id", user["org_id"])
        .eq("finding_id", finding_id)
        .eq("provider", "jira")
        .execute()
        .data
    )


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
