"""
run_correlation — turns detected software (product/version) into CVE findings via NVD.

Runs AFTER the analyst so it can dedupe against vulns the scanners already reported,
and BEFORE threat_intel so the correlated findings get the same KEV/EPSS enrichment.
No LLM: severity comes from real CVSS; exploitability from KEV/EPSS downstream.
"""

import hashlib
import logging
import re

from backend.agents.state import ScanState, AnalyzedFinding
from backend.core.cpe_intel import correlate_services
from backend.core.cve_intel import lookup_cves

logger = logging.getLogger(__name__)

# Matches CVE ids in raw scanner output (e.g. nmap's 'vulners' script lists them).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "info"}


def _severity(row: dict | None) -> str:
    if not row:
        return "low"
    sev = (row.get("cvss_severity") or "").lower()
    if sev in _SEVERITY_MAP:
        return _SEVERITY_MAP[sev]
    # NVD a veces rellena cvss_score antes que baseSeverity: derivar de los umbrales.
    score = row.get("cvss_score")
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if row.get("in_kev"):
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    if row.get("in_kev"):
        return "high"
    return "low"


def _fingerprint(asset_id: str, cve_id: str) -> str:
    return hashlib.sha256(f"{asset_id}:cpe:{cve_id}".encode()).hexdigest()


def run_correlation(state: ScanState) -> ScanState:
    if not state.detected_services:
        return state

    correlated = correlate_services(state.detected_services)
    if not correlated:
        return state

    # cve_id -> the software label it was matched from (first wins).
    cve_to_software: dict[str, str] = {}
    for label, cve_ids in correlated.items():
        for cid in cve_ids:
            cve_to_software.setdefault(cid, label)

    # Dedupe: don't re-add CVEs the scanners already surfaced — either as a finding's
    # cve_ids, or mentioned in raw scanner output (e.g. nmap 'vulners'). The raw-output
    # scan is deterministic, so dedup doesn't depend on the LLM extracting CVEs.
    already = {c.upper() for f in state.analyzed_findings for c in f.cve_ids}
    for rf in state.raw_findings:
        output = str(rf.raw.get("output", ""))
        already.update(m.upper() for m in _CVE_RE.findall(output))
    new_cves = [c for c in cve_to_software if c.upper() not in already]
    if not new_cves:
        logger.info("run_correlation: all correlated CVEs already reported by scanners")
        return state

    intel = lookup_cves(new_cves)

    added = 0
    for cve_id in new_cves:
        row = intel.get(cve_id)
        software = cve_to_software[cve_id]
        description = (row.get("short_description") if row else None) or (
            f"{cve_id} applies to detected software {software} (NVD version match)."
        )
        try:
            state.analyzed_findings.append(
                AnalyzedFinding(
                    id=_fingerprint(state.asset.id, cve_id),
                    title=f"{cve_id} in {software}",
                    description=description,
                    severity=_severity(row),
                    cvss_score=row.get("cvss_score") if row else None,
                    cve_ids=[cve_id],
                    confidence=0.7,
                    rationale=(
                        f"Version-based CPE correlation: detected {software} matches NVD "
                        f"records for {cve_id}. Not confirmed by active probing — may be a "
                        f"false positive if the package was patched without a version bump."
                    ),
                    source_service=software,
                )
            )
            added += 1
        except Exception as e:
            logger.warning("run_correlation: skipping %s: %s", cve_id, e)

    logger.info(
        "run_correlation: %d services -> %d new CVE findings (%d already reported)",
        len(state.detected_services),
        added,
        len(cve_to_software) - len(new_cves),
    )
    return state
