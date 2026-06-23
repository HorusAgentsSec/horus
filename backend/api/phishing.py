"""
AuthPhishing — employee management, phishing simulation campaigns, and email templates.

Endpoints:
  Employees  GET/POST/DELETE /phishing/employees
             POST /phishing/employees/import  (bulk CSV)
  Templates  GET/POST        /phishing/templates
             POST            /phishing/templates/generate  (AI generation)
             GET/PATCH/DELETE /phishing/templates/:id
  Campaigns  GET/POST   /phishing/campaigns
             GET/PATCH  /phishing/campaigns/:id
             POST       /phishing/campaigns/:id/launch
             GET        /phishing/campaigns/:id/results
  Honeypot   GET  /phishing/track/:token       (no auth — the employee follows this link)

DEPRECATED (use /hibp/* instead):
  HIBP       POST /phishing/hibp/check        → use /hibp/check
             GET  /phishing/breaches          → use /hibp/breaches
"""

import csv
import io
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from supabase import Client

from backend.api.auth import get_db
from backend.api.deps import require_role
from backend.api.phishing_library import SYSTEM_TEMPLATES
from backend.core.config import settings
from backend.core.audit import log_action

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/phishing", tags=["phishing"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class EmployeeCreate(BaseModel):
    email: str
    full_name: str | None = None
    department: str | None = None


class EmployeeImport(BaseModel):
    csv_text: str   # raw CSV: email[,full_name[,department]]


class TemplateCreate(BaseModel):
    name: str
    subject: str = ""
    body_html: str = ""
    is_public: bool = False


class TemplateUpdate(BaseModel):
    name: str | None = None
    subject: str | None = None
    body_html: str | None = None
    is_public: bool | None = None


class TemplateGenerateRequest(BaseModel):
    name: str
    objective: str = "click"
    scenario: str   # free-text description of the phishing scenario
    is_public: bool = False


class CampaignCreate(BaseModel):
    name: str
    objective: str = "click"
    context_asset_ids: list[str] = []
    schedule_cron: str | None = None
    template_id: str | None = None


class CampaignUpdate(BaseModel):
    name: str | None = None
    objective: str | None = None
    context_asset_ids: list[str] | None = None
    schedule_cron: str | None = None
    status: str | None = None


class LaunchRequest(BaseModel):
    employee_ids: list[str]   # which employees to target in this run


# ── Employees ─────────────────────────────────────────────────────────────────

@router.get("/employees")
async def list_employees(user=Depends(require_role("analyst")), db: Client = Depends(get_db)):
    employees = (
        db.table("employees")
        .select("id, email, full_name, department, hibp_checked_at, credential_breaches(id, breach_name, breach_date, data_classes, is_sensitive)")
        .eq("org_id", user["org_id"])
        .order("email")
        .execute()
        .data
    )
    return employees


@router.post("/employees", status_code=201)
async def create_employee(
    body: EmployeeCreate, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    existing = (
        db.table("employees")
        .select("id")
        .eq("org_id", user["org_id"])
        .eq("email", body.email.lower())
        .execute()
        .data
    )
    if existing:
        raise HTTPException(409, "employee already exists")
    row = (
        db.table("employees")
        .insert({
            "org_id": user["org_id"],
            "email": body.email.lower(),
            "full_name": body.full_name,
            "department": body.department,
        })
        .execute()
        .data[0]
    )
    log_action(user["org_id"], user["id"], "employee.created", entity_type="employee", entity_id=row["id"])
    return row


@router.post("/employees/import", status_code=201)
async def import_employees(
    body: EmployeeImport, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    reader = csv.DictReader(io.StringIO(body.csv_text.strip()))
    # Support both header and headerless (email first column)
    rows_to_insert = []
    errors = []
    for i, row in enumerate(reader):
        email = (row.get("email") or row.get("Email") or list(row.values())[0] or "").strip().lower()
        if not email or "@" not in email:
            errors.append(f"row {i + 1}: invalid email '{email}'")
            continue
        rows_to_insert.append({
            "org_id": user["org_id"],
            "email": email,
            "full_name": (row.get("full_name") or row.get("Full Name") or "").strip() or None,
            "department": (row.get("department") or row.get("Department") or "").strip() or None,
        })

    if not rows_to_insert:
        raise HTTPException(400, f"no valid employees found; errors: {errors}")

    inserted = (
        db.table("employees")
        .upsert(rows_to_insert, on_conflict="org_id,email")
        .execute()
        .data
    )
    log_action(user["org_id"], user["id"], "employee.import", metadata={"count": len(inserted)})
    return {"imported": len(inserted), "errors": errors}


@router.delete("/employees/{employee_id}", status_code=204)
async def delete_employee(
    employee_id: str, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    db.table("employees").update(
        {"deleted_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", employee_id).eq("org_id", user["org_id"]).execute()
    log_action(user["org_id"], user["id"], "employee.deleted", entity_type="employee", entity_id=employee_id)


# ── HIBP ── DEPRECATED: use /hibp/* instead ───────────────────────────────────

# DEPRECATED: POST /hibp/check (in backend.api.hibp) is the canonical endpoint.
# This endpoint is kept for backward compatibility only and will be removed in v2.0.
@router.post("/hibp/check")
async def hibp_check(user=Depends(require_role("admin")), db: Client = Depends(get_db)):
    """DEPRECATED: Use POST /hibp/check instead. Manually trigger a HIBP domain check for this org."""
    if not settings.hibp_check_enabled:
        raise HTTPException(400, "HIBP check is disabled in settings")
    if not settings.hibp_api_key:
        raise HTTPException(400, "hibp_api_key not configured — add it to your .env")

    org_row = db.table("organizations").select("domain").eq("id", user["org_id"]).single().execute()
    domain = (org_row.data or {}).get("domain", "")
    if not domain:
        raise HTTPException(400, "organisation has no domain configured")

    from backend.core.hibp import check_org
    result = check_org(user["org_id"], domain)
    log_action(user["org_id"], user["id"], "hibp.check", metadata=result)
    return result


# DEPRECATED: GET /hibp/breaches (in backend.api.hibp) is the canonical endpoint.
# This endpoint is kept for backward compatibility only and will be removed in v2.0.
@router.get("/breaches")
async def list_breaches(user=Depends(require_role("analyst")), db: Client = Depends(get_db)):
    """DEPRECATED: Use GET /hibp/breaches instead."""
    breaches = (
        db.table("credential_breaches")
        .select("*, employees(email, full_name)")
        .eq("org_id", user["org_id"])
        .order("discovered_at", desc=True)
        .execute()
        .data
    )
    return breaches


# ── Templates ─────────────────────────────────────────────────────────────────

@router.get("/templates")
async def list_templates(user=Depends(require_role("analyst")), db: Client = Depends(get_db)):
    return (
        db.table("phishing_templates")
        .select("*")
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
        .execute()
        .data
    )


@router.post("/templates", status_code=201)
async def create_template(
    body: TemplateCreate, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    row = (
        db.table("phishing_templates")
        .insert({
            "org_id": user["org_id"],
            "name": body.name,
            "subject": body.subject,
            "body_html": body.body_html,
            "is_public": body.is_public,
            "created_by": user["id"],
        })
        .execute()
        .data[0]
    )
    log_action(user["org_id"], user["id"], "template.created", entity_type="phishing_template", entity_id=row["id"])
    return row


@router.post("/templates/generate", status_code=201)
async def generate_template(
    body: TemplateGenerateRequest, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    """Generate a phishing email template via AI and save it."""
    valid_objectives = {"click", "credentials", "report"}
    if body.objective not in valid_objectives:
        raise HTTPException(400, f"objective must be one of {sorted(valid_objectives)}")

    org_row = db.table("organizations").select("name").eq("id", user["org_id"]).single().execute()
    org_name = (org_row.data or {}).get("name", "")

    from backend.agents.phishing_agent import PhishingAgent
    agent = PhishingAgent()
    generated = agent.generate_template(
        objective=body.objective,
        scenario=body.scenario,
        org_name=org_name,
    )

    row = (
        db.table("phishing_templates")
        .insert({
            "org_id": user["org_id"],
            "name": body.name,
            "subject": generated.get("subject", ""),
            "body_html": generated.get("body_html", ""),
            "is_public": body.is_public,
            "created_by": user["id"],
        })
        .execute()
        .data[0]
    )
    log_action(user["org_id"], user["id"], "template.generated", entity_type="phishing_template", entity_id=row["id"])
    return {**row, "pretext": generated.get("pretext", "")}


@router.get("/templates/community")
async def list_community_templates(user=Depends(require_role("analyst")), db: Client = Depends(get_db)):
    """Return all public templates — system library + user-contributed — enriched with org name."""
    rows = (
        _service_supabase.table("phishing_templates")
        .select("id, name, subject, body_html, created_at, org_id, organizations(name)")
        .eq("is_public", True)
        .order("created_at", desc=True)
        .execute()
        .data
    )
    result = []
    for r in rows:
        org_data = r.pop("organizations", None) or {}
        r["org_name"] = org_data.get("name", "Unknown org")
        r["is_own"] = r["org_id"] == user["org_id"]
        result.append(r)

    # Append built-in library templates (always available, org-independent)
    sys_ids_in_db = {r["id"] for r in result}
    for tpl in SYSTEM_TEMPLATES:
        if tpl["id"] not in sys_ids_in_db:
            result.append({**tpl, "is_own": False})

    return result


@router.get("/templates/{template_id}")
async def get_template(
    template_id: str, user=Depends(require_role("analyst")), db: Client = Depends(get_db)
):
    rows = (
        db.table("phishing_templates")
        .select("*")
        .eq("id", template_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "template not found")
    return rows[0]


@router.patch("/templates/{template_id}")
async def update_template(
    template_id: str, body: TemplateUpdate,
    user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "no fields to update")
    updates["updated_at"] = "now()"
    rows = (
        db.table("phishing_templates")
        .update(updates)
        .eq("id", template_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "template not found")
    return rows[0]


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template(
    template_id: str, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    db.table("phishing_templates").update(
        {"deleted_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", template_id).eq("org_id", user["org_id"]).execute()
    log_action(user["org_id"], user["id"], "template.deleted", entity_type="phishing_template", entity_id=template_id)


@router.post("/templates/{template_id}/fork", status_code=201)
async def fork_template(
    template_id: str, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    """Clone a public community template into the current org's library."""
    # System library templates are resolved from the built-in list (no DB row)
    if template_id.startswith("sys-"):
        matches = [t for t in SYSTEM_TEMPLATES if t["id"] == template_id]
        if not matches:
            raise HTTPException(404, "system template not found")
        source = matches[0]
    else:
        rows = (
            _service_supabase.table("phishing_templates")
            .select("name, subject, body_html")
            .eq("id", template_id)
            .eq("is_public", True)
            .execute()
            .data
        )
        if not rows:
            raise HTTPException(404, "public template not found")
        source = rows[0]
    row = (
        db.table("phishing_templates")
        .insert({
            "org_id": user["org_id"],
            "name": source["name"],
            "subject": source["subject"],
            "body_html": source["body_html"],
            "is_public": False,
            "created_by": user["id"],
        })
        .execute()
        .data[0]
    )
    log_action(user["org_id"], user["id"], "template.forked", entity_type="phishing_template", entity_id=row["id"],
               metadata={"source_id": template_id})
    return row


# ── Campaigns ─────────────────────────────────────────────────────────────────

@router.get("/campaigns")
async def list_campaigns(user=Depends(require_role("analyst")), db: Client = Depends(get_db)):
    return (
        db.table("phishing_campaigns")
        .select("*")
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
        .execute()
        .data
    )


@router.post("/campaigns", status_code=201)
async def create_campaign(
    body: CampaignCreate, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    valid_objectives = {"click", "credentials", "report"}
    if body.objective not in valid_objectives:
        raise HTTPException(400, f"objective must be one of {sorted(valid_objectives)}")
    row = (
        db.table("phishing_campaigns")
        .insert({
            "org_id": user["org_id"],
            "name": body.name,
            "objective": body.objective,
            "context_asset_ids": body.context_asset_ids,
            "schedule_cron": body.schedule_cron,
            "template_id": body.template_id,
            "created_by": user["id"],
        })
        .execute()
        .data[0]
    )
    log_action(user["org_id"], user["id"], "campaign.created", entity_type="phishing_campaign", entity_id=row["id"])
    return row


@router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str, user=Depends(require_role("analyst")), db: Client = Depends(get_db)
):
    rows = (
        db.table("phishing_campaigns")
        .select("*")
        .eq("id", campaign_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "campaign not found")
    return rows[0]


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(
    campaign_id: str,
    body: CampaignUpdate,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "no fields to update")
    rows = (
        db.table("phishing_campaigns")
        .update(updates)
        .eq("id", campaign_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(404, "campaign not found")
    return rows[0]


@router.delete("/campaigns/{campaign_id}", status_code=204)
async def delete_campaign(
    campaign_id: str, user=Depends(require_role("admin")), db: Client = Depends(get_db)
):
    db.table("phishing_campaigns").update(
        {"deleted_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", campaign_id).eq("org_id", user["org_id"]).execute()
    log_action(user["org_id"], user["id"], "campaign.deleted", entity_type="phishing_campaign", entity_id=campaign_id)


@router.post("/campaigns/{campaign_id}/launch")
async def launch_campaign(
    campaign_id: str,
    body: LaunchRequest,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """
    Generate personalised phishing emails and (when SMTP is configured) send them.
    Each target gets a unique tracking token embedded in their honeypot URL.
    """
    campaign_rows = (
        db.table("phishing_campaigns")
        .select("*")
        .eq("id", campaign_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not campaign_rows:
        raise HTTPException(404, "campaign not found")
    campaign = campaign_rows[0]

    if campaign["status"] not in ("draft", "scheduled"):
        raise HTTPException(400, f"cannot launch a campaign in '{campaign['status']}' status")

    if not body.employee_ids:
        raise HTTPException(400, "employee_ids must not be empty")

    # Load employees
    employees = (
        db.table("employees")
        .select("id, email, full_name")
        .eq("org_id", user["org_id"])
        .in_("id", body.employee_ids)
        .execute()
        .data
    )
    if not employees:
        raise HTTPException(400, "no matching employees found")

    # Load asset context
    assets = []
    if campaign["context_asset_ids"]:
        assets = (
            db.table("assets")
            .select("id, name, asset_type")
            .eq("org_id", user["org_id"])
            .in_("id", campaign["context_asset_ids"])
            .execute()
            .data
        )

    # Load org name
    org_row = db.table("organizations").select("name").eq("id", user["org_id"]).single().execute()
    org_name = (org_row.data or {}).get("name", "")

    # Load template if campaign has one
    template = None
    if campaign.get("template_id"):
        tpl_rows = (
            db.table("phishing_templates")
            .select("subject, body_html")
            .eq("id", campaign["template_id"])
            .eq("org_id", user["org_id"])
            .execute()
            .data
        )
        template = tpl_rows[0] if tpl_rows else None

    from backend.agents.phishing_agent import PhishingAgent
    agent = PhishingAgent()

    targets_created = []
    send_errors = []

    # Mark campaign as running
    db.table("phishing_campaigns").update({"status": "running", "launched_at": "now()"}).eq("id", campaign_id).execute()

    for emp in employees:
        token = secrets.token_urlsafe(32)
        tracking_url = f"{settings.phishing_base_url}/api/phishing/track/{token}"
        emp_name = emp.get("full_name") or emp["email"].split("@")[0]

        if template:
            email_content = PhishingAgent.apply_template(
                body_html=template["body_html"],
                subject=template["subject"],
                employee_name=emp_name,
                employee_email=emp["email"],
                tracking_url=tracking_url,
            )
        else:
            email_content = agent.generate_email(
                employee_name=emp_name,
                employee_email=emp["email"],
                objective=campaign["objective"],
                asset_context=assets,
                tracking_url=tracking_url,
                org_name=org_name,
            )

        # Upsert target row with generated content
        target = (
            db.table("phishing_targets")
            .upsert(
                {
                    "campaign_id": campaign_id,
                    "org_id": user["org_id"],
                    "employee_id": emp["id"],
                    "tracking_token": token,
                    "email_subject": email_content.get("subject", ""),
                    "email_body_html": email_content.get("body_html", ""),
                },
                on_conflict="campaign_id,employee_id",
            )
            .execute()
            .data[0]
        )
        targets_created.append(target)

        # Attempt to send the email via SMTP integration if configured
        _try_send_phishing_email(
            db, user["org_id"], emp["email"], email_content, send_errors
        )

    # Mark completed (async send errors don't block the campaign)
    db.table("phishing_campaigns").update({"status": "completed", "completed_at": "now()"}).eq("id", campaign_id).execute()

    log_action(
        user["org_id"], user["id"], "campaign.launched",
        entity_type="phishing_campaign", entity_id=campaign_id,
        metadata={"targets": len(targets_created), "send_errors": len(send_errors)},
    )
    return {
        "targets": len(targets_created),
        "send_errors": send_errors[:10],
    }


def _try_send_phishing_email(
    db: Client,
    org_id: str,
    to_email: str,
    email_content: dict,
    errors: list,
) -> None:
    """Best-effort: send via the first active email integration. Log failures, never raise."""
    try:
        from backend.core.notify import send_email
        integrations = (
            db.table("integrations")
            .select("config")
            .eq("org_id", org_id)
            .eq("type", "email")
            .eq("enabled", True)
            .limit(1)
            .execute()
            .data
        )
        if not integrations:
            return
        config = dict(integrations[0]["config"] or {})
        config["to"] = [to_email]

        subject = email_content.get("subject", "[Security Simulation]")
        body_html = email_content.get("body_html", "")

        from email.message import EmailMessage
        import smtplib
        from backend.core.config import settings as s

        host = config.get("smtp_host") or s.smtp_host
        if not host:
            return

        port = int(config.get("smtp_port") or s.smtp_port)
        user = config.get("smtp_user") or s.smtp_user
        password = config.get("smtp_password") or s.smtp_password
        from_addr = config.get("from_addr") or s.smtp_from or user
        use_tls = config.get("use_tls", s.smtp_use_tls)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_email
        msg.set_content("Please view this email in an HTML-capable client.")
        msg.add_alternative(body_html, subtype="html")

        with smtplib.SMTP(host, port, timeout=15) as server:
            if use_tls:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.send_message(msg)

    except Exception as e:
        logger.warning("phishing: failed to send to %s: %s", to_email, e)
        errors.append({"email": to_email, "error": str(e)[:200]})


@router.get("/campaigns/{campaign_id}/results")
async def campaign_results(
    campaign_id: str, user=Depends(require_role("analyst")), db: Client = Depends(get_db)
):
    # Verify access
    campaign = (
        db.table("phishing_campaigns")
        .select("id, name, objective, status")
        .eq("id", campaign_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not campaign:
        raise HTTPException(404, "campaign not found")

    targets = (
        db.table("phishing_targets")
        .select("*")
        .eq("campaign_id", campaign_id)
        .execute()
        .data
    )

    # Enrich with employee data (manual join — no PostgREST FK declared)
    emp_ids = list({t["employee_id"] for t in targets if t.get("employee_id")})
    if emp_ids:
        emp_rows = (
            db.table("employees")
            .select("id, email, full_name")
            .in_("id", emp_ids)
            .execute()
            .data
        )
        emp_map = {e["id"]: e for e in emp_rows}
        for t in targets:
            t["employees"] = emp_map.get(t.get("employee_id"))

    total = len(targets)
    clicked = sum(1 for t in targets if t.get("link_clicked_at"))
    entered_creds = sum(1 for t in targets if t.get("creds_entered_at"))
    reported = sum(1 for t in targets if t.get("reported_at"))

    return {
        "campaign": campaign[0],
        "summary": {
            "total": total,
            "clicked": clicked,
            "entered_credentials": entered_creds,
            "reported": reported,
            "safe": total - clicked - reported,
        },
        "targets": targets,
    }


# ── Honeypot tracker — no auth required ──────────────────────────────────────

_AWARENESS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Awareness Training</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0a0e1a; color: #e8e4d9;
          display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
  .card {{ background: #141929; border: 1px solid #2a3050; border-radius:12px;
           padding:2rem 2.5rem; max-width:480px; text-align:center; }}
  .icon {{ font-size:3rem; margin-bottom:1rem; }}
  h1 {{ color:#e4b84d; margin:0 0 1rem; font-size:1.4rem; }}
  p {{ color:#9da8c7; line-height:1.6; }}
  .tip {{ background:#1e2a1a; border:1px solid #2a4a2a; border-radius:8px;
          padding:1rem; margin-top:1.5rem; color:#7ecb7e; font-size:.9rem; }}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🎣</div>
  <h1>This was a phishing simulation</h1>
  <p>You clicked a link in a security awareness test. Don't worry — no real harm done.
     This simulation helps your organisation measure and improve its security posture.</p>
  <div class="tip">
    <strong>Next time, look for:</strong><br>
    Unexpected urgency · Mismatched sender domains · Generic greetings · Suspicious links
  </div>
</div>
</body>
</html>"""

from backend.core.supabase_client import supabase as _service_supabase


@router.get("/track/{token}", response_class=HTMLResponse, include_in_schema=False)
async def honeypot_track(token: str, request: Request):
    """
    Called when a targeted employee clicks the phishing link.
    Records the click event and shows the security awareness page.
    No auth — the employee is not logged into Horus.
    """
    try:
        rows = (
            _service_supabase.table("phishing_targets")
            .select("id, link_clicked_at")
            .eq("tracking_token", token)
            .execute()
            .data
        )
        if rows and not rows[0].get("link_clicked_at"):
            _service_supabase.table("phishing_targets").update(
                {"link_clicked_at": "now()"}
            ).eq("id", rows[0]["id"]).execute()
    except Exception as e:
        logger.warning("honeypot track error for token %s: %s", token[:8], e)

    return HTMLResponse(content=_AWARENESS_HTML, status_code=200)
