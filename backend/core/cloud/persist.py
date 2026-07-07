"""
Cloud finding persistence — provider-agnostic.

Hangs cloud findings off a per-account asset (type 'cloud') so they flow through the existing
findings list, dashboard and SSVC prioritization. Shared by the AWS and GCP audits; the finding's
`provider` field drives the asset host prefix and the raw_data, so adding a provider needs no change
here.
"""

import logging
from datetime import datetime, timezone

from backend.core import ssvc
from backend.core.cloud.finding import CloudFinding
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def get_cloud_asset_id(org_id: str, provider: str, account_id: str) -> str:
    """Find (or create) the asset representing this cloud account, to hang findings off."""
    host = f"{provider}:{account_id}"
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
            "name": f"{provider.upper()} account {account_id}",
            "host": host,
            "type": "cloud",
            "is_internal": False,
            "metadata": {"provider": provider, "account_id": account_id},
        })
        .execute()
    )
    return created.data[0]["id"]


def persist_cloud_finding(org_id: str, asset_id: str, f: CloudFinding) -> None:
    """Upsert one cloud finding (idempotent on org_id,fingerprint)."""
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
                "tool": f"cloud_{f.provider}",
                "source": "cloud",
                "provider": f.provider,
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


def persist_findings(org_id: str, provider: str, account_id: str, findings: list[CloudFinding]) -> dict:
    """Upsert all findings for one account and return a summary (account, count, by_severity)."""
    asset_id = get_cloud_asset_id(org_id, provider, account_id)
    for f in findings:
        try:
            persist_cloud_finding(org_id, asset_id, f)
        except Exception:
            logger.exception("failed to persist cloud finding %s", f.dedup_key)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"account_id": account_id, "findings": len(findings), "by_severity": by_sev}
