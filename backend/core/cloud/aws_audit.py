"""
AWS audit orchestration — glue between credentials, collection, checks and persistence.

run_aws_audit reads an org's stored AWS integration, takes a read-only inventory snapshot, runs the
pure checks, and persists the results via the shared cloud persistence layer (findings hung off a
per-account "cloud" asset). Re-running is idempotent (deterministic per-resource fingerprints).
Note (MVP): findings that no longer fire are NOT auto-resolved yet.
"""

import logging

from backend.core.cloud import aws_checks, aws_cloudtrail, aws_collect, persist
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def run_aws_audit(org_id: str, integration_id: str) -> dict:
    """Run a full AWS audit for one integration. Returns a summary dict (for the job record).

    Two layers: CSPM/CI-CD config checks (aws_checks) plus CloudTrail activity detections
    (aws_cloudtrail). Both produce findings persisted the same way."""
    integration = (
        supabase.table("integrations")
        .select("*")
        .eq("id", integration_id)
        .eq("org_id", org_id)
        .single()
        .execute()
    )
    if not integration.data or integration.data.get("type") != "aws":
        raise ValueError(f"AWS integration {integration_id} not found for org {org_id}")

    config = integration.data.get("config") or {}
    session = aws_collect.build_session(config)
    inventory = aws_collect.collect(session)
    account_id = inventory.get("account_id", "unknown")

    findings = aws_checks.evaluate(inventory)
    # Activity layer: scan recent CloudTrail events for compromise/risky-change signals.
    lookback = int(config.get("cloudtrail_lookback_hours", 24))
    events = aws_collect.collect_cloudtrail(session, lookback_hours=lookback)
    findings += aws_cloudtrail.evaluate_events(events)

    summary = persist.persist_findings(org_id, "aws", account_id, findings)
    summary["cloudtrail_events_scanned"] = len(events)
    logger.info("AWS audit org=%s account=%s findings=%d (cloudtrail events=%d)",
                org_id, account_id, summary["findings"], len(events))
    return summary
