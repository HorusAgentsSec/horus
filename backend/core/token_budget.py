"""
Token budget enforcement — per-org daily/weekly/monthly limits on LLM token consumption.

check_budget(org_id) is called before every pipeline run and iris_triage LLM call.
Returns {ok: True} when within budget, {ok: False, period, used, limit} when exceeded.

Usage is cached 5 min per org to avoid a DB round-trip on every agent call.
Threshold notifications (80% / 100%) are deduplicated in-memory per org+period+day.
"""

import logging
from datetime import datetime, timedelta, timezone

from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

# {org_id: (computed_at, {daily: N, weekly: N, monthly: N})}
_cache: dict[str, tuple[datetime, dict[str, int]]] = {}
_CACHE_TTL = 300  # seconds

# Dedup: {f"{org_id}:{period}:{date}:{pct}"} — resets on restart (acceptable)
_notified: set[str] = set()


def _usage(org_id: str) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    cached = _cache.get(org_id)
    if cached and (now - cached[0]).total_seconds() < _CACHE_TTL:
        return cached[1]

    cutoff = (now - timedelta(days=31)).isoformat()
    rows = (
        supabase.table("agent_runs")
        .select("tokens_used, started_at")
        .eq("org_id", org_id)
        .gte("started_at", cutoff)
        .execute()
        .data or []
    )

    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = day_start - timedelta(days=day_start.weekday())
    month_start = day_start.replace(day=1)

    daily = weekly = monthly = 0
    for r in rows:
        tokens = r.get("tokens_used") or 0
        raw = r.get("started_at") or ""
        try:
            ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts >= day_start:
            daily += tokens
        if ts >= week_start:
            weekly += tokens
        if ts >= month_start:
            monthly += tokens

    result = {"daily": daily, "weekly": weekly, "monthly": monthly}
    _cache[org_id] = (now, result)
    return result


def invalidate(org_id: str) -> None:
    """Call after recording new token usage so the next check is fresh."""
    _cache.pop(org_id, None)


def _notify(org_id: str, period: str, used: int, limit: int, pct: str) -> None:
    today = datetime.now(timezone.utc).date().isoformat()
    key = f"{org_id}:{period}:{today}:{pct}"
    if key in _notified:
        return
    _notified.add(key)
    try:
        recipients = (
            supabase.table("profiles")
            .select("id")
            .eq("org_id", org_id)
            .eq("role", "admin")
            .execute()
            .data or []
        )
        if not recipients:
            return
        at_limit = pct == "100"
        title = (
            f"Token budget exceeded — {period} limit reached"
            if at_limit
            else f"Token budget warning — {pct}% of {period} limit used"
        )
        body = f"{used:,} / {limit:,} tokens used this {period}."
        if at_limit:
            body += " AI agents are paused until the period resets."
        rows = [
            {
                "org_id": org_id,
                "user_id": r["id"],
                "type": "budget_alert",
                "title": title,
                "body": body,
                "metadata": {"period": period, "used": used, "limit": limit, "pct": pct},
            }
            for r in recipients
        ]
        supabase.table("notifications").insert(rows).execute()
        logger.info("token_budget: sent %s%% alert to org %s (%s: %d/%d)", pct, org_id, period, used, limit)
    except Exception as exc:
        logger.debug("token_budget: notification failed: %s", exc)


def check_budget(org_id: str) -> dict:
    """
    Returns {"ok": True} if within budget, or
    {"ok": False, "period": str, "used": int, "limit": int} if exceeded.
    Best-effort — any DB error returns {"ok": True} to avoid blocking scans.
    """
    try:
        row = (
            supabase.table("org_settings")
            .select("token_limit_daily, token_limit_weekly, token_limit_monthly")
            .eq("org_id", org_id)
            .execute()
            .data or []
        )
        limits = row[0] if row else {}
    except Exception:
        return {"ok": True}

    if not any(limits.get(f"token_limit_{p}") for p in ("daily", "weekly", "monthly")):
        return {"ok": True}

    usage = _usage(org_id)

    for period in ("daily", "weekly", "monthly"):
        limit = limits.get(f"token_limit_{period}")
        if not limit:
            continue
        used = usage[period]
        if used >= limit:
            _notify(org_id, period, used, limit, "100")
            return {"ok": False, "period": period, "used": used, "limit": limit}
        if used >= limit * 0.8:
            _notify(org_id, period, used, limit, "80")

    return {"ok": True}
