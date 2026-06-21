"""
AWS audit orchestration — glue between credentials, collection, checks and persistence.

run_aws_audit reads an org's stored AWS integration, takes a read-only inventory snapshot, runs the
pure checks, and persists the results via the shared cloud persistence layer (findings hung off a
per-account "cloud" asset). Re-running is idempotent (deterministic per-resource fingerprints).
Note (MVP): findings that no longer fire are NOT auto-resolved yet.
"""

import logging

from backend.core.cloud import aws_checks, aws_collect, persist
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def run_aws_audit(org_id: str, integration_id: str) -> dict:
    """Run a full AWS audit for one integration. Returns a summary dict (for the job record)."""
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

    session = aws_collect.build_session(integration.data.get("config") or {})
    inventory = aws_collect.collect(session)
    account_id = inventory.get("account_id", "unknown")
    findings = aws_checks.evaluate(inventory)

    summary = persist.persist_findings(org_id, "aws", account_id, findings)
    logger.info("AWS audit org=%s account=%s findings=%d", org_id, account_id, summary["findings"])
    return summary
