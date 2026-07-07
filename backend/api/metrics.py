from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from supabase import Client
from backend.api.auth import get_current_user, get_db

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/tokens")
async def get_token_metrics(
    days: int = 30,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """
    Returns aggregated token consumption and model usage metrics for the active organization.
    Ensures org isolation via the scoped database client.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    runs = (
        db.table("agent_runs")
        .select("agent_type, status, tokens_used, model_used, started_at")
        .eq("org_id", user["org_id"])
        .gte("started_at", cutoff)
        .order("started_at", desc=False)
        .execute()
    )

    total_tokens = 0
    by_agent: dict[str, int] = {}
    by_model: dict[str, int] = {}
    by_date: dict[str, int] = {}

    for run in runs.data:
        tokens = run.get("tokens_used") or 0
        agent_type = run.get("agent_type")
        model = run.get("model_used") or "unknown"
        started_at = run.get("started_at")

        total_tokens += tokens
        if agent_type:
            by_agent[agent_type] = by_agent.get(agent_type, 0) + tokens

        by_model[model] = by_model.get(model, 0) + tokens

        if started_at:
            # Group by day YYYY-MM-DD
            date_str = started_at[:10]
            by_date[date_str] = by_date.get(date_str, 0) + tokens

    daily_usage = [{"date": k, "tokens": v} for k, v in sorted(by_date.items())]

    return {
        "total_tokens": total_tokens,
        "by_agent": by_agent,
        "by_model": by_model,
        "daily_usage": daily_usage,
    }
