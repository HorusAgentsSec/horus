"""
Audit trail read API — exposes the append-only audit_log for admins.

The log is written by backend.core.audit.log_action across the app (team changes,
asset deletes, permission policy changes, scan triggers, AI suggestion reviews).
Here we only read it, RLS-scoped to the caller's org, and enrich each entry with
the acting user's display name so the frontend can show a human-readable trail.
"""

from fastapi import APIRouter, Depends, Query
from supabase import Client

from backend.api.auth import get_db
from backend.api.deps import require_role

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit_log(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    action: str | None = None,
    entity_type: str | None = None,
    actor_id: str | None = None,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    """Returns a paginated, newest-first slice of the org's audit trail."""
    offset = (page - 1) * per_page

    query = (
        db.table("audit_log")
        .select("*", count="exact")
        .eq("org_id", user["org_id"])
    )
    if action:
        query = query.eq("action", action)
    if entity_type:
        query = query.eq("entity_type", entity_type)
    if actor_id:
        query = query.eq("actor_id", actor_id)

    result = (
        query.order("created_at", desc=True)
        .range(offset, offset + per_page - 1)
        .execute()
    )
    entries = result.data

    # Enrich user actors with their display name (single lookup, no N+1).
    user_actor_ids = {
        e["actor_id"] for e in entries if e.get("actor_type") == "user" and e.get("actor_id")
    }
    name_map: dict[str, str | None] = {}
    if user_actor_ids:
        profiles = (
            db.table("profiles")
            .select("id, full_name")
            .in_("id", list(user_actor_ids))
            .execute()
        )
        name_map = {p["id"]: p.get("full_name") for p in profiles.data}

    for e in entries:
        e["actor_name"] = name_map.get(e.get("actor_id"))

    return {
        "entries": entries,
        "total": result.count or 0,
        "page": page,
        "per_page": per_page,
    }
