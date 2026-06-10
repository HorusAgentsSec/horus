"""
Watchtower — continuous exposure monitoring.

A scan is a point-in-time snapshot; threats emerge every day. Watchtower closes that gap:
each day, after the KEV/EPSS sync refreshes `cve_intel`, it re-correlates every asset's
persisted software inventory against CVEs that *just* became known-exploited — WITHOUT
re-scanning — and raises an alert (a finding + notification) for any new exposure.

This is the recurring-value engine: it turns a one-off scan into perpetual monitoring.

Determinism, no LLM: "newly exploited" comes straight from CISA KEV dates, the inventory→CVE
mapping reuses the cached NVD CPE correlation (`cves_for`), and severity comes from real CVSS.

The heavy lifting (`match_exposures`, `_severity`) is pure and unit-tested. DB and feed
access is lazy-imported so those helpers can be imported without a configured backend.

Run manually:  python -m backend.core.watchtower
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable

from backend.core.config import settings

logger = logging.getLogger(__name__)

# cve_intel.cvss_severity (critical/high/medium/low/none) -> findings.severity enum.
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "info",
}


def _severity(intel: dict) -> str:
    """Map a cve_intel row to a findings severity. A KEV CVE with no CVSS is still being
    actively exploited, so it floors at 'high' rather than 'info'."""
    sev = (intel.get("cvss_severity") or "").lower()
    if sev in _SEVERITY_MAP:
        return _SEVERITY_MAP[sev]
    return "high"


def _severity_spike(intel: dict) -> str:
    """Severity for an EPSS-spike alert. Unlike KEV, a spike is a *probability* signal, not
    confirmed exploitation, so with no CVSS it floors at 'medium' rather than 'high'."""
    sev = (intel.get("cvss_severity") or "").lower()
    if sev in _SEVERITY_MAP:
        return _SEVERITY_MAP[sev]
    return "medium"


def is_epss_spike(row: dict, floor: float, delta: float) -> bool:
    """Pure spike test: the new EPSS score is at/above `floor` and rose by at least `delta`
    since the previous sync. Needs both a current and a previous score."""
    cur = row.get("epss_score")
    prev = row.get("epss_previous")
    if cur is None or prev is None:
        return False
    return cur >= floor and (cur - prev) >= delta


def match_exposures(
    items: list[dict],
    urgent: dict[str, dict],
    correlate_fn: Callable[[str, str], list[str]],
    already: set[tuple[str, str]],
) -> list[tuple[dict, str, dict]]:
    """
    Pure core of the watchtower: intersect inventory with newly-urgent CVEs.

    items        — inventory rows ({asset_id, product, version, ...}) for one org.
    urgent       — {cve_id: intel_row} of CVEs that just became known-exploited.
    correlate_fn — (product, version) -> [cve_id]; the cached CPE→CVE lookup.
    already      — set of (asset_id, cve_id) already alerted; MUTATED to dedup within this run.

    Returns new (item, cve_id, intel_row) tuples to alert on.
    """
    out: list[tuple[dict, str, dict]] = []
    corr_cache: dict[tuple[str, str], list[str]] = {}  # correlate each (product, version) once
    for item in items:
        pv = (item["product"], item["version"])
        if pv not in corr_cache:
            corr_cache[pv] = correlate_fn(item["product"], item["version"])
        for cve_id in corr_cache[pv]:
            if cve_id not in urgent:
                continue
            key = (item["asset_id"], cve_id)
            if key in already:
                continue
            already.add(key)
            out.append((item, cve_id, urgent[cve_id]))
    return out


def _newly_kev_cves(lookback_days: int) -> dict[str, dict]:
    """CVEs that entered CISA KEV within the lookback window. {cve_id: intel_row}."""
    from backend.core.supabase_client import supabase

    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=lookback_days)).isoformat()
    res = (
        supabase.table("cve_intel")
        .select("*")
        .eq("in_kev", True)
        .gte("kev_date_added", cutoff)
        .execute()
    )
    return {r["cve_id"]: {**r, "_reason": "kev_added"} for r in (res.data or [])}


def _epss_spikes(floor: float, delta: float) -> dict[str, dict]:
    """CVEs (not in KEV) whose EPSS score just spiked day-over-day. {cve_id: intel_row}.
    The floor keeps the candidate set small; the exact spike test runs in Python.
    NOTE: PostgREST caps at ~1000 rows — fine because epss_score >= floor (≥0.5) is a high bar."""
    from backend.core.supabase_client import supabase

    res = (
        supabase.table("cve_intel")
        .select("*")
        .eq("in_kev", False)
        .gte("epss_score", floor)
        .not_.is_("epss_previous", "null")
        .execute()
    )
    return {
        r["cve_id"]: {**r, "_reason": "epss_spike"}
        for r in (res.data or [])
        if is_epss_spike(r, floor, delta)
    }


def _presentation(cve_id: str, software: str, intel: dict, reason: str) -> dict:
    """Title / severity / exploitability / description / rationale for an alert, by reason.
    KEV = confirmed exploitation; EPSS spike = a sharp rise in exploitation *probability*."""
    if reason == "epss_spike":
        cur = intel.get("epss_score") or 0.0
        prev = intel.get("epss_previous") or 0.0
        desc = (intel.get("short_description") or "").strip() or (
            f"{cve_id} affects {software}, already in your inventory. Its EPSS exploitation "
            f"probability jumped from {prev:.0%} to {cur:.0%} — an early warning that exploitation "
            f"is becoming likely, often before a CVE reaches CISA KEV."
        )
        return {
            "title": f"{cve_id} rising exploitation risk — affects {software}",
            "severity": _severity_spike(intel),
            "exploitability": "high",
            "description": desc,
            "rationale": (
                f"Continuous exposure monitoring: EPSS rose from {prev:.0%} to {cur:.0%} "
                f"(day-over-day spike) for a CVE matching software in your inventory "
                f"(version-based correlation). No re-scan was performed."
            ),
        }
    # default: kev_added
    desc = (intel.get("short_description") or "").strip() or (
        f"{cve_id} entered CISA KEV (known exploited in the wild) and affects {software}, "
        f"which is already in your inventory."
    )
    return {
        "title": f"{cve_id} now actively exploited — affects {software}",
        "severity": _severity(intel),
        "exploitability": "active",
        "description": desc,
        "rationale": (
            "Continuous exposure monitoring: this CVE entered CISA KEV and matches software "
            "already in your inventory (version-based correlation). No re-scan was performed; "
            "may be a false positive if the package was patched without a version bump."
        ),
    }


def _raise_alerts(org_id: str, alerts: list[tuple[dict, str, dict]]) -> list[dict]:
    """Create a finding + watchtower_alerts row for each new exposure. Returns the list of
    alert summaries actually persisted (for notification). Each intel row carries a '_reason'
    ('kev_added' | 'epss_spike') that shapes the alert's wording and severity."""
    from backend.core.supabase_client import supabase

    now = datetime.now(timezone.utc).isoformat()
    created: list[dict] = []
    for item, cve_id, intel in alerts:
        reason = intel.get("_reason", "kev_added")
        product, version = item["product"], item["version"]
        software = f"{product} {version}"
        p = _presentation(cve_id, software, intel, reason)
        severity = p["severity"]
        fingerprint = hashlib.sha256(
            f"{item['asset_id']}:watchtower:{cve_id}".encode()
        ).hexdigest()

        finding_id = None
        try:
            res = (
                supabase.table("findings")
                .upsert(
                    {
                        "org_id": org_id,
                        "asset_id": item["asset_id"],
                        "title": p["title"],
                        "description": p["description"],
                        "severity": severity,
                        "cvss_score": intel.get("cvss_score"),
                        "cve_ids": [cve_id],
                        "fingerprint": fingerprint,
                        "raw_data": {
                            "source": "watchtower",
                            "watchtower_reason": reason,
                            "exploitability": p["exploitability"],
                            "source_service": software,
                            "epss_score": intel.get("epss_score"),
                            "epss_previous": intel.get("epss_previous"),
                            "kev_date_added": intel.get("kev_date_added"),
                            "confidence": 0.7,
                            "rationale": p["rationale"],
                        },
                        "last_seen_at": now,
                    },
                    on_conflict="org_id,fingerprint",
                )
                .execute()
            )
            finding_id = res.data[0]["id"] if res.data else None
        except Exception:
            logger.exception("watchtower: failed to upsert finding for %s", cve_id)

        try:
            supabase.table("watchtower_alerts").upsert(
                {
                    "org_id": org_id,
                    "asset_id": item["asset_id"],
                    "cve_id": cve_id,
                    "product": product,
                    "version": version,
                    "reason": reason,
                    "severity": severity,
                    "finding_id": finding_id,
                },
                on_conflict="asset_id,cve_id",
            ).execute()
            created.append(
                {
                    "cve_id": cve_id,
                    "product": product,
                    "version": version,
                    "asset_id": item["asset_id"],
                    "severity": severity,
                    "reason": reason,
                }
            )
        except Exception:
            logger.exception("watchtower: failed to record alert for %s", cve_id)

    if created:
        try:
            from backend.core.notify import notify_watchtower

            # Notify per kind so the wording matches (confirmed exploitation vs rising risk).
            for kind in ("kev_added", "epss_spike"):
                subset = [c for c in created if c.get("reason") == kind]
                if subset:
                    notify_watchtower(org_id, subset, kind=kind)
        except Exception:
            logger.exception("watchtower: notification failed for org %s", org_id)
    return created


def run_watchtower_generator(lookback_days: int | None = None):
    """
    Generator that yields progress strings, then finally yields the summary dict.
    """
    if not settings.watchtower_enabled:
        yield {"skipped": True}
        return
    lookback_days = (
        settings.watchtower_lookback_days if lookback_days is None else lookback_days
    )

    from backend.core.cpe_intel import cves_for
    from backend.core.supabase_client import supabase

    yield "Fetching newly exploited CVEs from KEV..."
    kev = _newly_kev_cves(lookback_days)
    yield f"Found {len(kev)} newly-KEV CVEs."

    yield "Checking for EPSS spikes..."
    spikes = (
        _epss_spikes(settings.watchtower_epss_floor, settings.watchtower_epss_spike_delta)
        if settings.watchtower_epss_spike_enabled
        else {}
    )
    if settings.watchtower_epss_spike_enabled:
        yield f"Found {len(spikes)} EPSS spikes."

    urgent = {**spikes, **kev}
    if not urgent:
        logger.info(
            "watchtower: no newly-KEV or EPSS-spiking CVEs (lookback %d days)", lookback_days
        )
        yield "No urgent CVEs found. Check complete."
        yield {"urgent_cves": 0, "alerts": 0}
        return

    yield "Fetching asset inventory..."
    inventory = supabase.table("asset_inventory").select("*").execute().data or []
    by_org: dict[str, list[dict]] = {}
    for row in inventory:
        by_org.setdefault(row["org_id"], []).append(row)
    
    yield f"Analyzing {len(inventory)} assets across {len(by_org)} organizations..."

    existing = (
        supabase.table("watchtower_alerts").select("asset_id, cve_id").execute().data or []
    )
    already = {(a["asset_id"], a["cve_id"]) for a in existing}

    total = 0
    for org_id, items in by_org.items():
        yield f"Correlating {len(items)} assets for org {org_id[:8]}..."
        matches = match_exposures(items, urgent, cves_for, already)
        if matches:
            yield f"Found {len(matches)} new exposures for org {org_id[:8]}! Raising alerts..."
            total += len(_raise_alerts(org_id, matches))
            try:
                from backend.core.posture import snapshot_posture
                snapshot_posture(org_id)
            except Exception:
                logger.exception("watchtower: posture snapshot failed for org %s", org_id)

    logger.info(
        "watchtower: %d urgent CVEs (%d newly-KEV, %d EPSS-spike), %d new alerts",
        len(urgent), len(kev), len(spikes), total,
    )
    yield "Watchtower check complete."
    yield {
        "urgent_cves": len(urgent),
        "newly_kev": len(kev),
        "epss_spikes": len(spikes),
        "alerts": total,
        "orgs": len(by_org),
    }

def run_watchtower(lookback_days: int | None = None) -> dict:
    """
    Daily continuous-exposure check across all orgs. Returns a summary dict.
    Consumes run_watchtower_generator synchronously.
    """
    result = {}
    for item in run_watchtower_generator(lookback_days):
        if isinstance(item, dict):
            result = item
    return result


def run_ransomware_check(org_id: str, db=None) -> dict:
    """
    Check all assets in an org against ransomware.live victim database.

    For each asset's domain, queries ransomware.live and creates a finding
    for each match. Returns a summary: {checked: N, matches: M}.

    If db is None, imports supabase_client (lazy import for testing).
    """
    from backend.core.ransomware_intel import check_domain, normalize_victim
    from backend.core.supabase_client import supabase

    if db is None:
        db = supabase

    logger.info(f"ransomware.live: checking org {org_id}")

    # Fetch all assets for the org
    try:
        assets_rows = db.table("assets").select("id, host").eq("org_id", org_id).eq("is_active", True).execute().data or []
    except Exception as e:
        logger.error(f"ransomware.live: failed to fetch assets for org {org_id}: {e}")
        return {"checked": 0, "matches": 0}

    if not assets_rows:
        logger.info(f"ransomware.live: no active assets for org {org_id}")
        return {"checked": 0, "matches": 0}

    now = datetime.now(timezone.utc).isoformat()
    checked = 0
    matches = 0
    findings_created = []

    for asset in assets_rows:
        asset_id = asset["id"]
        host = (asset.get("host") or "").strip()
        if not host:
            continue

        checked += 1

        # Check this asset's domain against ransomware.live
        victims = check_domain(host)
        if not victims:
            continue

        # For each victim match, create a finding
        for victim in victims:
            normalized = normalize_victim(victim)
            group = normalized.get("group", "Unknown Group")
            discovered = normalized.get("discovered_at", "Unknown Date")

            # Deterministic fingerprint: ransomware:{group}:{domain}
            domain_normalized = (host or "").lower().strip()
            fingerprint = hashlib.sha256(
                f"ransomware:{group}:{domain_normalized}".encode()
            ).hexdigest()[:32]

            title = f"Ransomware group {group} listed {domain_normalized} as victim"
            description = (
                f"The ransomware group '{group}' has listed {domain_normalized} "
                f"as a victim on their leak site. Discovered: {discovered}. "
                f"Post title: {normalized.get('title', 'N/A')}"
            )

            try:
                res = db.table("findings").upsert(
                    {
                        "org_id": org_id,
                        "asset_id": asset_id,
                        "title": title,
                        "description": description,
                        "severity": "critical",
                        "source": "ransomware.live",
                        "is_noise": False,
                        "fingerprint": fingerprint,
                        "raw_data": {
                            "source": "ransomware.live",
                            **normalized,
                        },
                        "last_seen_at": now,
                    },
                    on_conflict="org_id,fingerprint",
                ).execute()
                if res.data:
                    matches += 1
                    findings_created.append(res.data[0].get("id"))
            except Exception as e:
                logger.warning(f"ransomware.live: failed to upsert finding for {group}/{domain_normalized}: {e}")

    logger.info(
        f"ransomware.live: checked {checked} assets, found {matches} ransomware matches for org {org_id}"
    )
    return {"checked": checked, "matches": matches}


def run_ioc_check(org_id: str, db=None) -> dict:
    """
    Check all assets in an org against ThreatFox and URLhaus IOC databases.

    For each asset's host (IP or domain), queries both ThreatFox and URLhaus and creates
    findings for matches. Returns a summary: {checked: N, threatfox_matches: M, urlhaus_matches: K}.

    If db is None, imports supabase_client (lazy import for testing).
    """
    from backend.core.abuse_intel import check_threatfox, check_urlhaus
    from backend.core.supabase_client import supabase

    if db is None:
        db = supabase

    logger.info(f"ioc_check: checking org {org_id}")

    # Fetch all assets for the org
    try:
        assets_rows = db.table("assets").select("id, host").eq("org_id", org_id).eq("is_active", True).execute().data or []
    except Exception as e:
        logger.error(f"ioc_check: failed to fetch assets for org {org_id}: {e}")
        return {"checked": 0, "threatfox_matches": 0, "urlhaus_matches": 0}

    if not assets_rows:
        logger.info(f"ioc_check: no active assets for org {org_id}")
        return {"checked": 0, "threatfox_matches": 0, "urlhaus_matches": 0}

    now = datetime.now(timezone.utc).isoformat()
    checked = 0
    threatfox_matches = 0
    urlhaus_matches = 0

    for asset in assets_rows:
        asset_id = asset["id"]
        host = (asset.get("host") or "").strip()
        if not host:
            continue

        checked += 1

        # Check against ThreatFox
        threatfox_result = check_threatfox(host)
        if threatfox_result.get("found"):
            for threat in threatfox_result.get("threats", []):
                malware = threat.get("malware") or threat.get("threat_type") or "Unknown"
                fingerprint = hashlib.sha256(
                    f"threatfox:{host}:{malware}".encode()
                ).hexdigest()[:32]

                title = f"Asset {host} listed as IOC in ThreatFox ({malware})"
                description = (
                    f"The asset {host} is listed in ThreatFox as an indicator of compromise. "
                    f"Threat type: {threat.get('threat_type', 'Unknown')}. "
                    f"Malware: {malware}. "
                    f"Confidence: {threat.get('confidence_level', 'Unknown')}%. "
                    f"First seen: {threat.get('first_seen', 'Unknown')}."
                )

                try:
                    res = db.table("findings").upsert(
                        {
                            "org_id": org_id,
                            "asset_id": asset_id,
                            "title": title,
                            "description": description,
                            "severity": "critical",
                            "source": "threatfox",
                            "is_noise": False,
                            "fingerprint": fingerprint,
                            "raw_data": {
                                "source": "threatfox",
                                "ioc_type": threat.get("ioc_type"),
                                "threat_type": threat.get("threat_type"),
                                "malware": malware,
                                "confidence_level": threat.get("confidence_level"),
                                "first_seen": threat.get("first_seen"),
                                "last_seen": threat.get("last_seen"),
                                "reference": threat.get("reference"),
                                "tags": threat.get("tags"),
                            },
                            "last_seen_at": now,
                        },
                        on_conflict="org_id,fingerprint",
                    ).execute()
                    if res.data:
                        threatfox_matches += 1
                except Exception as e:
                    logger.warning(f"ioc_check: failed to upsert ThreatFox finding for {host}: {e}")

        # Check against URLhaus
        urlhaus_result = check_urlhaus(host)
        if urlhaus_result.get("found"):
            fingerprint = hashlib.sha256(
                f"urlhaus:{host}".encode()
            ).hexdigest()[:32]

            title = f"Asset {host} hosts malicious URLs (URLhaus)"
            url_count = len(urlhaus_result.get("urls", []))
            url_list = ", ".join([u.get("url", "") for u in urlhaus_result.get("urls", [])[:5]])
            if url_count > 5:
                url_list += f", ... and {url_count - 5} more"

            description = (
                f"The asset {host} is listed in URLhaus as hosting malicious content. "
                f"Found {url_count} malicious URL(s): {url_list}"
            )

            try:
                res = db.table("findings").upsert(
                    {
                        "org_id": org_id,
                        "asset_id": asset_id,
                        "title": title,
                        "description": description,
                        "severity": "high",
                        "source": "urlhaus",
                        "is_noise": False,
                        "fingerprint": fingerprint,
                        "raw_data": {
                            "source": "urlhaus",
                            "urls": urlhaus_result.get("urls", []),
                            "url_count": url_count,
                        },
                        "last_seen_at": now,
                    },
                    on_conflict="org_id,fingerprint",
                ).execute()
                if res.data:
                    urlhaus_matches += 1
            except Exception as e:
                logger.warning(f"ioc_check: failed to upsert URLhaus finding for {host}: {e}")

    logger.info(
        f"ioc_check: checked {checked} assets, found {threatfox_matches} ThreatFox + {urlhaus_matches} URLhaus matches for org {org_id}"
    )
    return {"checked": checked, "threatfox_matches": threatfox_matches, "urlhaus_matches": urlhaus_matches}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print(run_watchtower())
