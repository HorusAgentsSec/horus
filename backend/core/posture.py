"""
Security posture scoring — the deterministic risk number behind the executive timeline.

A posture snapshot reduces the org's open findings to one comparable number plus the
severity breakdown, captured per day. Plotted over time it tells the "our risk is going
down" story that justifies the subscription.

Scoring is deliberately simple and defensible (no LLM, no magic): a severity-weighted count
of open findings, with an extra penalty for findings under active exploitation (CISA KEV).
Lower is better. `score_from_counts` is pure and unit-tested; DB access is lazy-imported so
it can be used without a configured backend.

Run manually to snapshot every org now:  python -m backend.core.posture
"""

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Severity weights for the risk score. Tuned so each step up roughly doubles weight; a
# single critical outweighs several mediums. Info findings are noise → zero.
WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

# Active exploitation (CISA KEV) is the urgent signal — each such finding adds this on top
# of its severity weight, so a KEV-active item dominates the score.
KEV_BONUS = 10

SEVERITIES = ("critical", "high", "medium", "low", "info")


def score_from_counts(counts: dict[str, int], kev_active: int = 0) -> int:
    """Pure risk score from a severity->count map plus the actively-exploited count.
    Lower is better; 0 means no open risk."""
    score = sum(WEIGHTS.get(sev, 0) * int(n or 0) for sev, n in counts.items())
    score += KEV_BONUS * int(kev_active or 0)
    return score


def is_suppressed(raw_data: dict | None) -> bool:
    """True if the validation debate judged this finding a likely false positive. Suppressed
    findings stay visible in the Findings list but don't inflate the board-facing risk score —
    the platform acts on its own calibrated judgement (KEV-active is never marked false positive,
    so actively-exploited risk is never hidden)."""
    return (raw_data or {}).get("verdict") == "false_positive"


def compute_posture(org_id: str) -> dict:
    """Aggregate the org's CURRENT open findings into a posture record (not persisted).
    Excludes findings the validation debate flagged as likely false positives."""
    from backend.core.supabase_client import supabase

    rows = (
        supabase.table("findings")
        .select("severity, raw_data")
        .eq("org_id", org_id)
        .eq("status", "open")
        .execute()
        .data
        or []
    )
    counts = {sev: 0 for sev in SEVERITIES}
    kev_active = 0
    open_findings = 0
    for r in rows:
        if is_suppressed(r.get("raw_data")):
            continue
        open_findings += 1
        sev = r.get("severity") or "info"
        if sev in counts:
            counts[sev] += 1
        if (r.get("raw_data") or {}).get("exploitability") == "active":
            kev_active += 1

    return {
        "risk_score": score_from_counts(counts, kev_active),
        "open_findings": open_findings,
        "kev_active": kev_active,
        **counts,
    }


def snapshot_posture(org_id: str) -> dict:
    """Compute and upsert today's posture snapshot for one org. Best-effort: posture
    tracking must never break a scan or job. Returns the snapshot record."""
    from backend.core.supabase_client import supabase

    record = compute_posture(org_id)
    try:
        supabase.table("posture_snapshots").upsert(
            {
                "org_id": org_id,
                "snapshot_date": datetime.now(timezone.utc).date().isoformat(),
                **record,
            },
            on_conflict="org_id,snapshot_date",
        ).execute()
        logger.info("posture: snapshot for org %s risk=%d", org_id, record["risk_score"])
    except Exception:
        logger.exception("posture: snapshot failed for org %s", org_id)
    return record


def load_timeline(client, org_id: str, days: int = 90) -> dict:
    """Read an org's posture snapshots over the last `days` (oldest first) and derive the
    current value + trend. Shared by the JSON timeline API (RLS client) and the PDF/email
    report (service-role client) so they never diverge. `client` is any supabase Client —
    the caller decides the security context. Returns {timeline, current, trend_delta};
    trend_delta < 0 means risk fell (good)."""
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()
    rows = (
        client.table("posture_snapshots")
        .select("snapshot_date, risk_score, open_findings, kev_active, critical, high, medium, low, info")
        .eq("org_id", org_id)
        .gte("snapshot_date", cutoff)
        .order("snapshot_date", desc=False)
        .execute()
        .data
        or []
    )
    timeline = [{"date": r.pop("snapshot_date"), **r} for r in rows]
    current = timeline[-1] if timeline else None
    delta = (
        current["risk_score"] - timeline[0]["risk_score"] if len(timeline) >= 2 else 0
    )
    return {"timeline": timeline, "current": current, "trend_delta": delta}


def snapshot_all_orgs() -> int:
    """Snapshot every org's posture — the daily cron entry point. Captures days with no
    scan (aging findings, new Watchtower alerts) so the timeline has a point every day."""
    from backend.core.supabase_client import supabase

    orgs = supabase.table("organizations").select("id").execute().data or []
    for o in orgs:
        snapshot_posture(o["id"])
    logger.info("posture: snapshotted %d orgs", len(orgs))
    return len(orgs)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print("snapshotted orgs:", snapshot_all_orgs())
