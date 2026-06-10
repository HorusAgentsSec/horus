"""IntelligenceX dark web search API — admin-only."""

import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import intelx

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/intel", tags=["intel"])


class IntelSearchRequest(BaseModel):
    term: str
    type: str = "domain"  # "domain", "ip", or "email"


@router.post("/search")
async def search_intelx(
    body: IntelSearchRequest,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """
    Search IntelligenceX for mentions of a domain, IP, or email on dark web sources.

    Returns: {results: [...], total: N, darkweb_count: N}

    Requires intelx_api_key to be configured in org settings.
    """
    org_id = user["org_id"]

    # Fetch API key from org settings
    settings_row = (
        db.table("org_settings")
        .select("intelx_api_key")
        .eq("org_id", org_id)
        .execute()
        .data
    )
    api_key = settings_row[0].get("intelx_api_key") if settings_row else None

    if not api_key:
        raise HTTPException(400, "IntelligenceX API key not configured. Configure in Settings.")

    # Perform search
    try:
        results = intelx.search(body.term, api_key, max_results=10)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Count dark web results
    darkweb_count = sum(1 for r in results if intelx.is_darkweb_result(r))

    # TODO: Create findings for dark web results that match org assets
    # For now, just return results without automatic finding creation

    return {
        "results": results,
        "total": len(results),
        "darkweb_count": darkweb_count,
    }
