"""
run_threat_intel — enriches analyzed findings with CVE context and exploitability.

DETERMINISTIC: single lookup against the local cve_intel table (CISA KEV + FIRST EPSS),
synced daily by backend.core.cve_intel. Zero tokens, trusted data.

Exploitability is derived from real signals:
  - in KEV (exploited in the wild)        -> "active"
  - EPSS >= 0.5 (high exploit probability) -> "high"
  - EPSS >= 0.1                            -> "medium"
  - EPSS > 0                               -> "low"
  - otherwise / no CVE match               -> "none"
"""

import logging

from backend.agents.state import ScanState, EnrichedFinding
from backend.core.cve_intel import lookup_cves

logger = logging.getLogger(__name__)


def _exploitability(in_kev: bool, epss: float | None) -> str:
    if in_kev:
        return "active"
    if epss is None:
        return "none"
    if epss >= 0.5:
        return "high"
    if epss >= 0.1:
        return "medium"
    if epss > 0:
        return "low"
    return "none"


def _best_intel(cve_ids: list[str], intel: dict[str, dict]) -> dict | None:
    """Among a finding's CVEs, pick the most threatening one (KEV first, then EPSS)."""
    matches = [intel[c] for c in cve_ids if c in intel]
    if not matches:
        return None
    return max(
        matches,
        key=lambda r: (bool(r.get("in_kev")), r.get("epss_score") or 0.0),
    )


def _threat_context(row: dict | None) -> str:
    if row is None:
        return "No CVE intelligence match; exploitability assessed as unknown."
    parts = []
    if row.get("in_kev"):
        added = row.get("kev_date_added") or "an unknown date"
        parts.append(f"Listed in CISA KEV (exploited in the wild) since {added}.")
        if row.get("kev_ransomware"):
            parts.append("Known use in ransomware campaigns.")
    epss = row.get("epss_score")
    if epss is not None:
        pct = row.get("epss_percentile")
        pct_str = ""
        if isinstance(pct, (int, float)):
            top = (1 - pct) * 100
            pct_str = " (top <1%)" if top < 1 else f" (top {top:.0f}%)"
        parts.append(f"EPSS exploitation probability {epss:.2%}{pct_str}.")
    return " ".join(parts) or "CVE present in catalog; no active-exploitation signal."


def run_threat_intel(state: ScanState) -> ScanState:
    if not state.analyzed_findings:
        return state

    all_cves = [c for f in state.analyzed_findings for c in f.cve_ids]
    intel = lookup_cves(all_cves)

    enriched = []
    kev_hits = 0
    for f in state.analyzed_findings:
        row = _best_intel(f.cve_ids, intel)
        in_kev = bool(row and row.get("in_kev"))
        epss = row.get("epss_score") if row else None
        if in_kev:
            kev_hits += 1
        enriched.append(
            EnrichedFinding(
                finding_id=f.id,
                threat_context=_threat_context(row),
                exploitability=_exploitability(in_kev, epss),
                public_exploits_exist=in_kev or (epss is not None and epss >= 0.5),
                references=(row.get("refs") or []) if row else [],
            )
        )

    state.enriched_findings = enriched
    logger.info(
        "run_threat_intel: enriched %d findings via cve_intel (%d in KEV), 0 tokens",
        len(enriched),
        kev_hits,
    )
    return state
