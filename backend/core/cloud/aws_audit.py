"""
AWS audit orchestration — glue between credentials, collection, checks and findings.

run_aws_audit reads an org's stored AWS integration, takes a read-only inventory snapshot, runs the
pure checks, and upserts the results as findings hung off a per-account "cloud" asset (so they show
up in the existing Findings list, dashboard and SSVC prioritization with no special-casing).

Findings are deterministic-fingerprinted by the check's dedup_key, so re-running an audit updates in
place instead of duplicating. Note (MVP): findings that no longer fire are NOT auto-resolved yet.
"""

import logging
from datetime import datetime, timezone

from backend.core import ssvc
from backend.core.cloud import aws_checks, aws_collect
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def _get_cloud_asset_id(org_id: str, account_id: str) -> str:
    """Find (or create) the asset that represents this AWS account, to hang findings off."""
    host = f"aws:{account_id}"
    existing = (
        supabase.table("assets")
        .select("id")
        .eq("org_id", org_id)
        .eq("type", "cloud")
        .eq("host", host)
        .limit(1)
        .execute()
    )
    if existing.data:
        return existing.data[0]["id"]
    created = (
        supabase.table("assets")
        .insert({
            "org_id": org_id,
            "name": f"AWS account {account_id}",
            "host": host,
            "type": "cloud",
            "is_internal": False,
            "metadata": {"provider": "aws", "account_id": account_id},
        })
        .execute()
    )
    return created.data[0]["id"]


def _persist_cloud_finding(org_id: str, asset_id: str, f: aws_checks.CloudFinding) -> None:
    ssvc_result = ssvc.assess(
        exploitability=None, public_exploits_exist=False,
        severity=f.severity, cvss_score=None, is_internal=False,
    )
    supabase.table("findings").upsert(
        {
            "org_id": org_id,
            "asset_id": asset_id,
            "scan_id": None,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "cve_ids": [],
            "fingerprint": f.dedup_key,
            "is_noise": False,
            "raw_data": {
                "tool": "cloud_aws",
                "source": "cloud",
                "provider": "aws",
                "check_id": f.check_id,
                "service": f.service,
                "category": f.category,
                "resource": f.resource,
                "remediation": f.remediation,
                "confidence": 0.95,  # config-based checks are high-confidence (no probing guesswork)
                "rationale": f.description,
                "ssvc": ssvc_result.as_dict(),
            },
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        },
        on_conflict="org_id,fingerprint",
    ).execute()


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

    asset_id = _get_cloud_asset_id(org_id, account_id)
    for f in findings:
        try:
            _persist_cloud_finding(org_id, asset_id, f)
        except Exception:
            logger.exception("failed to persist cloud finding %s", f.dedup_key)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    logger.info("AWS audit org=%s account=%s findings=%d", org_id, account_id, len(findings))
    return {"account_id": account_id, "findings": len(findings), "by_severity": by_sev}
