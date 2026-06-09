"""
HaveIBeenPwned Domain Search client.

Queries the HIBP v3 Domain Search API for all breached accounts under an org's
domain, persists results to credential_breaches, updates karma_score on each
affected employee, and correlates the breach to assets the employee could access
(same org). Requires a paid HIBP API key (hibp_api_key in settings).

Rate limit: the Domain Search endpoint allows one request per domain per day in
practice. We run once daily via the scheduler — no in-process throttle needed.
"""

import logging
from datetime import date
from typing import Any

import httpx

from backend.core.config import settings
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

_KARMA_BREACH_PENALTY = 10   # points deducted per breach (floor: 0)
_KARMA_SENSITIVE_PENALTY = 20


def _hibp_headers() -> dict:
    return {
        "hibp-api-key": settings.hibp_api_key or "",
        "user-agent": "HorusSecurityPlatform/1.0",
    }


def _breached_accounts_for_domain(domain: str) -> list[dict]:
    """
    Returns a list of breach objects from HIBP for all accounts @domain.
    Each object has: Alias (local part), Breaches (list of breach metadata).
    """
    url = f"{settings.hibp_api_base}/breacheddomain/{domain}"
    try:
        with httpx.Client(timeout=settings.hibp_timeout_seconds) as client:
            resp = client.get(url, headers=_hibp_headers())
        if resp.status_code == 404:
            return []   # clean domain
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            logger.error("HIBP: invalid API key — configure hibp_api_key")
        else:
            logger.warning("HIBP domain search failed for %s: %s", domain, e)
        return []
    except Exception as e:
        logger.warning("HIBP request error for %s: %s", domain, e)
        return []


def _correlate_assets(org_id: str, employee_id: str) -> list[str]:
    """
    Returns asset IDs from the org that the employee could plausibly reach.
    Simple heuristic: all active assets for now; a future iteration could use
    access-control data (Sonar module) for finer correlation.
    """
    try:
        rows = (
            supabase.table("assets")
            .select("id")
            .eq("org_id", org_id)
            .eq("is_active", True)
            .execute()
            .data
        )
        return [r["id"] for r in rows]
    except Exception:
        return []


def _upsert_breach(
    org_id: str,
    employee_id: str,
    breach: dict[str, Any],
    email: str,
) -> None:
    breach_name = breach.get("Name", "")
    if not breach_name:
        return
    breach_date_str = breach.get("BreachDate")
    breach_date = None
    if breach_date_str:
        try:
            breach_date = date.fromisoformat(breach_date_str).isoformat()
        except ValueError:
            pass
    data_classes = breach.get("DataClasses") or []
    is_sensitive = "Passwords" in data_classes or "Auth Tokens" in data_classes

    asset_ids = _correlate_assets(org_id, employee_id)

    try:
        supabase.table("credential_breaches").upsert(
            {
                "org_id": org_id,
                "employee_id": employee_id,
                "breach_name": breach_name,
                "breach_date": breach_date,
                "data_classes": data_classes,
                "is_sensitive": is_sensitive,
                "correlated_asset_ids": asset_ids,
            },
            on_conflict="employee_id,breach_name",
        ).execute()
    except Exception as e:
        logger.warning("HIBP: failed to upsert breach %s for %s: %s", breach_name, email, e)


def _update_karma(employee_id: str, breach_count: int, sensitive_count: int) -> None:
    penalty = min(
        breach_count * _KARMA_BREACH_PENALTY + sensitive_count * _KARMA_SENSITIVE_PENALTY,
        100,
    )
    new_score = max(0, 100 - penalty)
    try:
        supabase.table("employees").update(
            {"karma_score": new_score, "hibp_checked_at": "now()"}
        ).eq("id", employee_id).execute()
    except Exception as e:
        logger.warning("HIBP: failed to update karma for %s: %s", employee_id, e)


def check_org(org_id: str, domain: str) -> dict:
    """
    Run a full HIBP check for one org's domain. Returns summary counts.
    Called by the scheduler and by the manual-trigger API endpoint.
    """
    if not settings.hibp_api_key:
        logger.info("HIBP check skipped: no API key configured")
        return {"skipped": True}

    logger.info("HIBP: checking domain %s for org %s", domain, org_id)
    raw = _breached_accounts_for_domain(domain)

    # Build a map: alias (lowercase) → list of breach objects
    breaches_by_alias: dict[str, list[dict]] = {}
    for entry in raw:
        alias = (entry.get("Alias") or "").lower()
        breaches_by_alias[alias] = entry.get("Breaches") or []

    # Load org employees
    employees = (
        supabase.table("employees")
        .select("id, email")
        .eq("org_id", org_id)
        .execute()
        .data
    ) or []

    affected = 0
    total_breaches = 0
    for emp in employees:
        email: str = emp["email"].lower()
        alias = email.split("@")[0]
        emp_breaches = breaches_by_alias.get(alias, [])
        if not emp_breaches:
            # Still update check timestamp even when clean
            try:
                supabase.table("employees").update(
                    {"hibp_checked_at": "now()"}
                ).eq("id", emp["id"]).execute()
            except Exception:
                pass
            continue

        affected += 1
        sensitive_count = 0
        for breach in emp_breaches:
            _upsert_breach(org_id, emp["id"], breach, email)
            if "Passwords" in (breach.get("DataClasses") or []):
                sensitive_count += 1
        _update_karma(emp["id"], len(emp_breaches), sensitive_count)
        total_breaches += len(emp_breaches)

    logger.info(
        "HIBP: %s — %d/%d employees affected, %d breach records",
        domain, affected, len(employees), total_breaches,
    )
    return {
        "domain": domain,
        "employees_checked": len(employees),
        "employees_affected": affected,
        "breach_records": total_breaches,
    }


def check_all_orgs() -> dict:
    """
    Run HIBP check for every org that has a domain configured.
    Called by the daily scheduler job.
    """
    orgs = supabase.table("organizations").select("id, domain").execute().data or []
    total = {"orgs": 0, "employees_checked": 0, "employees_affected": 0, "breach_records": 0}
    for org in orgs:
        domain = (org.get("domain") or "").strip()
        if not domain:
            continue
        result = check_org(org["id"], domain)
        if result.get("skipped"):
            break  # no key — stop immediately, no point iterating
        total["orgs"] += 1
        total["employees_checked"] += result.get("employees_checked", 0)
        total["employees_affected"] += result.get("employees_affected", 0)
        total["breach_records"] += result.get("breach_records", 0)
    return total
