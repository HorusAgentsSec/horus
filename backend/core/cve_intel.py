"""
CVE intelligence sync — populates the global `cve_intel` table from public feeds.

Sources (highest signal first):
  - CISA KEV : CVEs known to be exploited in the wild. Small (~1.2k), curated,
               the "this is urgent TODAY" signal.
  - FIRST EPSS: probability (0-1) a CVE will be exploited in the next 30 days.
               Large (~250k rows), lets us prioritise by real-world risk.

This replaces asking the LLM to recall CVE data (expensive + hallucinated). The
pipeline calls `lookup_cves()` for a deterministic JOIN against trusted data.

Run manually to populate immediately:
    python -m backend.core.cve_intel
"""

import csv
import gzip
import io
import logging
from datetime import datetime, timezone

import httpx

from backend.core.config import settings
from backend.core.supabase_client import supabase  # service-role: bypasses RLS

logger = logging.getLogger(__name__)


def _fetch_kev() -> dict[str, dict]:
    """Returns {cve_id: kev_fields} from the CISA KEV catalog."""
    resp = httpx.get(
        settings.kev_feed_url,
        timeout=settings.cve_sync_timeout_seconds,
        follow_redirects=True,
    )
    resp.raise_for_status()
    data = resp.json()

    released = data.get("dateReleased")  # ISO timestamp of the catalog
    out: dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        refs = []
        notes = v.get("notes")
        if notes:
            # KEV "notes" is a string of space/newline-separated URLs
            refs = [u for u in notes.replace("\n", " ").split(" ") if u.startswith("http")]
        out[cve_id] = {
            "in_kev": True,
            "kev_date_added": v.get("dateAdded"),
            "kev_ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "kev_name": v.get("vulnerabilityName"),
            "short_description": v.get("shortDescription"),
            "refs": refs,
            "source_updated_at": released,
        }
    logger.info("KEV: fetched %d exploited CVEs", len(out))
    return out


def _fetch_epss() -> dict[str, tuple[float, float]]:
    """Returns {cve_id: (epss_score, epss_percentile)} from the FIRST EPSS feed."""
    # FIRST redirects -current.csv.gz to the dated file via a relative 302.
    resp = httpx.get(
        settings.epss_feed_url,
        timeout=settings.cve_sync_timeout_seconds,
        follow_redirects=True,
    )
    resp.raise_for_status()
    raw = gzip.decompress(resp.content).decode("utf-8")

    out: dict[str, tuple[float, float]] = {}
    reader = csv.reader(io.StringIO(raw))
    for row in reader:
        if not row or row[0].startswith("#"):  # skip metadata comment line
            continue
        if row[0] == "cve":  # header
            continue
        try:
            out[row[0]] = (float(row[1]), float(row[2]))
        except (IndexError, ValueError):
            continue
    logger.info("EPSS: fetched %d scored CVEs", len(out))
    return out


def run_sync(include_epss: bool | None = None) -> int:
    """
    Fetches the feeds, merges them keyed by cve_id, and upserts into cve_intel.
    Returns the number of rows written.
    """
    include_epss = settings.cve_sync_include_epss if include_epss is None else include_epss
    now = datetime.now(timezone.utc).isoformat()

    kev = _fetch_kev()
    epss = _fetch_epss() if include_epss else {}

    # Snapshot yesterday's EPSS (current -> epss_previous) BEFORE the upsert overwrites the
    # scores, so Watchtower can detect day-over-day spikes. Best-effort: a snapshot failure must
    # not abort the sync (we'd just miss spike detection for one day).
    if epss:
        try:
            supabase.rpc("snapshot_epss").execute()
        except Exception:
            logger.exception("EPSS: snapshot_epss() failed; spike detection may miss this cycle")

    # Union of all CVE ids seen in either feed.
    cve_ids = set(kev) | set(epss)
    rows: list[dict] = []
    for cve_id in cve_ids:
        row = {
            "cve_id": cve_id,
            "in_kev": False,
            "kev_ransomware": False,
            "refs": [],
            "updated_at": now,
        }
        if cve_id in epss:
            row["epss_score"], row["epss_percentile"] = epss[cve_id]
        if cve_id in kev:
            row.update(kev[cve_id])
        rows.append(row)

    written = _batch_upsert(rows)
    logger.info("CVE sync complete: %d rows (%d in KEV)", written, len(kev))
    return written


def _batch_upsert(rows: list[dict]) -> int:
    batch = settings.cve_sync_batch_size
    written = 0
    for i in range(0, len(rows), batch):
        chunk = rows[i : i + batch]
        supabase.table("cve_intel").upsert(chunk, on_conflict="cve_id").execute()
        written += len(chunk)
        logger.debug("cve_intel upsert progress: %d/%d", written, len(rows))
    return written


def lookup_cves(cve_ids: list[str]) -> dict[str, dict]:
    """
    Deterministic enrichment for the pipeline: maps CVE ids to their intel row.
    Replaces the LLM "recall threat data" step. Unknown CVEs are simply absent.
    """
    ids = list({c for c in cve_ids if c})
    if not ids:
        return {}
    res = supabase.table("cve_intel").select("*").in_("cve_id", ids).execute()
    return {r["cve_id"]: r for r in (res.data or [])}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_sync()
