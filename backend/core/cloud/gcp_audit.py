"""
GCP audit orchestration — mirror of aws_audit for Google Cloud.

Reads an org's stored GCP integration, takes a read-only inventory snapshot, runs the pure checks,
and persists results via the shared cloud persistence layer. Re-running is idempotent. Note (MVP):
findings that no longer fire are NOT auto-resolved yet.
"""

import logging

from backend.core.cloud import gcp_checks, gcp_collect, persist
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def run_gcp_audit(org_id: str, integration_id: str) -> dict:
    """Run a full GCP audit for one integration. Returns a summary dict (for the job record)."""
    integration = (
        supabase.table("integrations")
        .select("*")
        .eq("id", integration_id)
        .eq("org_id", org_id)
        .single()
        .execute()
    )
    if not integration.data or integration.data.get("type") != "gcp":
        raise ValueError(f"GCP integration {integration_id} not found for org {org_id}")

    config = integration.data.get("config") or {}
    inventory = gcp_collect.collect(config)
    project_id = inventory.get("project_id", "unknown")
    findings = gcp_checks.evaluate(inventory)

    summary = persist.persist_findings(org_id, "gcp", project_id, findings)
    logger.info("GCP audit org=%s project=%s findings=%d", org_id, project_id, summary["findings"])
    return summary
