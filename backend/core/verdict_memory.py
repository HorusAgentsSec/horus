"""
Finding verdict memory — the reflection loop adapted from TradingAgents.

TradingAgents reflects on past trades and updates agent memory so it learns from outcomes. Our
analogue: when a human judges a finding (false positive / resolved / accepted / approved a fix), we
record that verdict against a *generalizable signature* of the finding. On future scans the
ValidationAgent recalls it and applies it as a prior — auto-suppressing a known false positive
without spending a debate, trusting a known-real one. Human feedback compounds into accuracy.

`finding_signature` is pure and unit-tested (it must produce the same key on the recording side —
the API, from a DB row — and the recall side — the pipeline, from an AnalyzedFinding). DB access is
lazy-imported and best-effort: verdict memory must never break a scan or a user action, and it
degrades to "no memory" if the table isn't present yet.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Human actions → the verdict they imply. Marking false positive is the only false_positive signal;
# resolving / accepting / approving a fix all mean the finding was real.
STATUS_TO_VERDICT = {
    "false_positive": "false_positive",
    "resolved": "confirmed",
    "accepted_risk": "confirmed",
}


def _slug(text: str) -> str:
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return "-".join(words[:6])


def finding_signature(
    *,
    source_service: str | None = None,
    cve_ids: list[str] | None = None,
    title: str | None = None,
) -> str:
    """A signature that generalizes across assets and scans, so a verdict carries forward.

    Priority:
      1. source_service ("nginx 1.18.0") → "svc:nginx"  — version-stripped product (correlated CVEs).
      2. cve_ids                          → "cve:CVE-2023-1234"  — the lowest CVE id (stable key).
      3. title                            → "title:potential-csrf"  — slug of the finding title
         (covers nmap http-* scripts and other scanner findings without a product or CVE).
    """
    if source_service:
        product = source_service.split()[0].lower()
        return f"svc:{product}"
    if cve_ids:
        return f"cve:{sorted(cve_ids)[0].upper()}"
    return f"title:{_slug(title) or 'unknown'}"


def record_human_verdict(
    org_id: str,
    finding_row: dict,
    verdict: str,
    source: str,
    user_id: str | None,
    db=None,
) -> None:
    """Append a human verdict for the finding's signature. Best-effort. `db` is an authed client
    (RLS) when called from the API; falls back to the service-role client otherwise."""
    if verdict not in ("false_positive", "confirmed"):
        return
    try:
        client = db
        if client is None:
            from backend.core.supabase_client import supabase
            client = supabase
        signature = finding_signature(
            source_service=(finding_row.get("raw_data") or {}).get("source_service"),
            cve_ids=finding_row.get("cve_ids"),
            title=finding_row.get("title"),
        )
        client.table("finding_verdicts").insert(
            {
                "org_id": org_id,
                "signature": signature,
                "verdict": verdict,
                "source": source,
                "finding_id": finding_row.get("id"),
                "created_by": user_id,
            }
        ).execute()
        logger.info("verdict memory: recorded %s for %s (org %s)", verdict, signature, org_id)
    except Exception:
        # Table may not exist yet, or RLS denied — never break the user's action.
        logger.debug("verdict memory: record skipped", exc_info=True)


def recall_community(signatures: set[str], client=None) -> dict[str, str]:
    """Anonymized, fleet-wide verdict per signature (the cross-customer flywheel) — only signatures
    where enough distinct orgs agreed (k-anonymity enforced in refresh_community_verdicts). Lets a
    new org benefit on day one. Best-effort; returns {} if the table isn't present yet."""
    if not signatures:
        return {}
    try:
        if client is None:
            from backend.core.supabase_client import supabase
            client = supabase
        rows = (
            client.table("community_verdicts")
            .select("signature, verdict")
            .in_("signature", sorted(signatures))
            .not_.is_("verdict", "null")
            .execute()
            .data
            or []
        )
        return {r["signature"]: r["verdict"] for r in rows}
    except Exception:
        logger.debug("verdict memory: community recall skipped", exc_info=True)
        return {}


def refresh_community() -> None:
    """Recompute the cross-org aggregate (community_verdicts) from finding_verdicts. Best-effort;
    runs server-side via RPC. Called from the daily job."""
    from backend.core.supabase_client import supabase

    supabase.rpc("refresh_community_verdicts").execute()
    logger.info("verdict memory: community aggregate refreshed")


def recall(org_id: str, signatures: set[str], client=None) -> dict[str, str]:
    """Latest human verdict per signature for an org. Best-effort; returns {} on any error (e.g.
    the table isn't migrated yet), so the pipeline simply runs without priors."""
    if not signatures:
        return {}
    try:
        if client is None:
            from backend.core.supabase_client import supabase
            client = supabase
        rows = (
            client.table("finding_verdicts")
            .select("signature, verdict, created_at")
            .eq("org_id", org_id)
            .in_("signature", sorted(signatures))
            .order("created_at", desc=True)
            .execute()
            .data
            or []
        )
        latest: dict[str, str] = {}
        for r in rows:  # rows are newest-first → first seen per signature wins
            latest.setdefault(r["signature"], r["verdict"])
        return latest
    except Exception:
        logger.debug("verdict memory: recall skipped", exc_info=True)
        return {}
