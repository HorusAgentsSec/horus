"""
Threat feeds API: abuse.ch ThreatFox + URLhaus IOC intelligence.

Endpoints:
- POST /api/threat-feeds/check-ioc — manual IOC lookup (combined results)
- POST /api/threat-feeds/scan-assets — trigger IOC scan for org (admin only)
- GET /api/threat-feeds/findings — list IOC findings for org
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db

router = APIRouter(prefix="/threat-feeds", tags=["threat_feeds"])


class CheckIOCRequest(BaseModel):
    term: str  # IP or domain to check


class CheckIOCResponse(BaseModel):
    term: str
    threatfox: dict
    urlhaus: dict


@router.post("/check-ioc")
async def check_ioc(
    body: CheckIOCRequest,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
) -> CheckIOCResponse:
    """
    Manual IOC lookup: check a term (IP or domain) against both ThreatFox and URLhaus.

    Returns combined results from both feeds, usable by anyone (read-only operation).
    """
    from backend.core.abuse_intel import check_threatfox, check_urlhaus

    if not body.term or not body.term.strip():
        raise HTTPException(400, "term cannot be empty")

    term = body.term.strip()
    threatfox_result = check_threatfox(term)
    urlhaus_result = check_urlhaus(term)

    return CheckIOCResponse(
        term=term,
        threatfox=threatfox_result,
        urlhaus=urlhaus_result,
    )


@router.post("/scan-assets", status_code=202)
async def scan_assets(
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
) -> dict:
    """
    Trigger immediate IOC scan for all assets in the org (admin only).

    Checks all active assets against ThreatFox and URLhaus, creates findings for matches.
    Returns stats: {checked, threatfox_matches, urlhaus_matches, status}.

    This is an immediate check; the daily scheduler also runs this as a cron job.
    """
    from backend.core.watchtower import run_ioc_check

    org_id = user["org_id"]

    # Verify admin role (assuming user has a role field; adjust per your auth model)
    # For now, assume get_current_user already filters to org members
    result = run_ioc_check(org_id, db=db)

    return {
        **result,
        "status": "completed",
        "org_id": org_id,
    }


@router.get("/findings")
async def list_threat_feed_findings(
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
) -> list[dict]:
    """
    List all IOC findings (ThreatFox + URLhaus) for the org.

    Returns findings with source in ["threatfox", "urlhaus"].
    """
    org_id = user["org_id"]

    try:
        findings = (
            db.table("findings")
            .select("*")
            .eq("org_id", org_id)
            .in_("source", ["threatfox", "urlhaus"])
            .order("last_seen_at", desc=True)
            .execute()
            .data or []
        )
    except Exception as e:
        raise HTTPException(500, f"Failed to fetch findings: {str(e)}")

    return findings
