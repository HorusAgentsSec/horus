"""HIBP credential exposure API — admin-only."""

import logging
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/hibp", tags=["hibp"])


class BreachCheckRequest(BaseModel):
    term: str
    type: str = "email"  # "email" or "domain"


@router.post("/check", status_code=202)
async def trigger_check(
    background_tasks: BackgroundTasks,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Launch HIBP domain check in background. Returns immediately."""
    from backend.core import hibp

    org = db.table("organizations").select("id, domain").eq("id", user["org_id"]).single().execute().data
    if not org or not org.get("domain"):
        raise HTTPException(400, "No domain configured for this org")
    background_tasks.add_task(hibp.check_org, user["org_id"], org["domain"])
    return {"status": "queued", "domain": org["domain"]}


@router.get("/breaches")
async def list_breaches(
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """All known credential breaches for this org, joined with employee info.

    Karma scores are included only if org_settings.employee_karma_enabled is true.
    """
    settings_row = db.table("org_settings").select("employee_karma_enabled").eq("org_id", user["org_id"]).execute().data
    karma_enabled = settings_row[0].get("employee_karma_enabled", False) if settings_row else False

    select_clause = "*, employees(full_name, email, department, karma_score)" if karma_enabled else "*, employees(full_name, email, department)"

    rows = (
        db.table("credential_breaches")
        .select(select_clause)
        .eq("org_id", user["org_id"])
        .order("breach_date", desc=True)
        .execute()
        .data or []
    )

    # If karma is disabled, remove karma_score from all employee records
    if not karma_enabled:
        for row in rows:
            if row.get("employees") and isinstance(row["employees"], dict):
                row["employees"].pop("karma_score", None)

    return rows


@router.post("/breach-directory/check")
async def check_breach_directory(
    body: BreachCheckRequest,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Check a single email or domain against BreachDirectory.org.

    Requires breach_directory_api_key configured in org_settings.
    """
    from backend.core import breach_directory

    org_id = user["org_id"]
    settings_row = (
        db.table("org_settings")
        .select("breach_directory_api_key")
        .eq("org_id", org_id)
        .execute()
        .data
    )
    api_key = settings_row[0].get("breach_directory_api_key") if settings_row else None

    if not api_key:
        raise HTTPException(
            400, "BreachDirectory API key not configured. Configure it in Settings → Integrations."
        )

    try:
        if body.type == "domain":
            result = breach_directory.check_domain(body.term, api_key)
        else:  # "email" or default
            result = breach_directory.check_email(body.term, api_key)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error("BreachDirectory check failed for %s: %s", body.term, e)
        raise HTTPException(500, f"BreachDirectory check failed: {str(e)}")


@router.get("/stats")
async def breach_stats(
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Summary stats: N employees affected, N sensitive breaches, avg karma score (if enabled).

    Karma is omitted if org_settings.employee_karma_enabled is false.
    """
    settings_row = db.table("org_settings").select("employee_karma_enabled").eq("org_id", user["org_id"]).execute().data
    karma_enabled = settings_row[0].get("employee_karma_enabled", False) if settings_row else False

    breaches = (
        db.table("credential_breaches")
        .select("employee_id, is_sensitive")
        .eq("org_id", user["org_id"])
        .execute()
        .data or []
    )
    employees_affected = len(set(b["employee_id"] for b in breaches))
    sensitive = sum(1 for b in breaches if b.get("is_sensitive"))

    result = {
        "total_breaches": len(breaches),
        "employees_affected": employees_affected,
        "sensitive_breaches": sensitive,
    }

    if karma_enabled:
        employees = (
            db.table("employees")
            .select("karma_score")
            .eq("org_id", user["org_id"])
            .execute()
            .data or []
        )
        scores = [e["karma_score"] for e in employees if e.get("karma_score") is not None]
        avg_karma = round(sum(scores) / len(scores)) if scores else 100
        result["avg_karma_score"] = avg_karma

    return result
