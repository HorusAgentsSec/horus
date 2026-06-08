from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from supabase import Client
from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core import verdict_memory
from backend.core.audit import log_action

router = APIRouter(prefix="/suggestions", tags=["suggestions"])


@router.post("/{suggestion_id}/approve")
async def approve_suggestion(
    suggestion_id: str,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    suggestion = _get_suggestion(db, suggestion_id, user["org_id"])
    if suggestion["status"] != "pending":
        raise HTTPException(status_code=400, detail="Suggestion is not pending")

    result = (
        db.table("agent_suggestions")
        .update(
            {
                "status": "approved",
                "reviewed_by": user["id"],
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        .eq("id", suggestion_id)
        .execute()
    )
    log_action(
        user["org_id"], user["id"], "suggestion.approved",
        entity_type="agent_suggestion", entity_id=suggestion_id,
        metadata={"action_type": suggestion.get("action_type"), "mode": suggestion.get("mode")},
    )

    # Approving a fix is a human confirming the finding is real → remember it for future scans.
    finding = (
        db.table("findings")
        .select("id, title, cve_ids, raw_data")
        .eq("id", suggestion["finding_id"])
        .eq("org_id", user["org_id"])
        .single()
        .execute()
        .data
    )
    if finding:
        verdict_memory.record_human_verdict(
            user["org_id"], finding, "confirmed", source="suggestion", user_id=user["id"], db=db
        )
    return result.data[0]


@router.post("/{suggestion_id}/reject")
async def reject_suggestion(
    suggestion_id: str,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    suggestion = _get_suggestion(db, suggestion_id, user["org_id"])
    if suggestion["status"] != "pending":
        raise HTTPException(status_code=400, detail="Suggestion is not pending")

    result = (
        db.table("agent_suggestions")
        .update(
            {
                "status": "rejected",
                "reviewed_by": user["id"],
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        .eq("id", suggestion_id)
        .execute()
    )
    log_action(
        user["org_id"], user["id"], "suggestion.rejected",
        entity_type="agent_suggestion", entity_id=suggestion_id,
        metadata={"action_type": suggestion.get("action_type")},
    )
    return result.data[0]


def _get_suggestion(db: Client, suggestion_id: str, org_id: str) -> dict:
    r = (
        db.table("agent_suggestions")
        .select("*")
        .eq("id", suggestion_id)
        .eq("org_id", org_id)
        .single()
        .execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    return r.data
