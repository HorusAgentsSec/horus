"""
CVE intelligence sync — populates the global `cve_intel` table from public feeds.

Sources (highest signal first):
  - CISA KEV : CVEs known to be exploited in the wild. Small (~1.2k), curated,
               the "this is urgent TODAY" signal.
  - FIRST EPSS: probability (0-1) a CVE will be exploited in the next 30 days.
               Large (~250k rows), lets us prioritise by real-world risk.
  - NVD CVSS  : CVSS base score + severity for every KEV CVE, fetched after the
               KEV/EPSS upsert so the cve_intel table always has actionable scores.

This replaces asking the LLM to recall CVE data (expensive + hallucinated). The
pipeline calls `lookup_cves()` for a deterministic JOIN against trusted data.

Run manually to populate immediately:
    python -m backend.core.cve_intel
"""

import csv
import gzip
import io
import logging
import time
from datetime import datetime, timezone

import httpx

from backend.core.config import settings
from backend.core.supabase_client import supabase  # service-role: bypasses RLS

logger = logging.getLogger(__name__)

# NVD CVSS enrichment rate limits (per-process; sync runs single-threaded).
# Without API key: 5 req / 30 s → use 4 to stay safely under.
# With API key   : 50 req / 30 s → use 40 to stay safely under.
_NVD_RATE_NO_KEY = 4    # requests per 30-second window
_NVD_RATE_WITH_KEY = 40  # requests per 30-second window
_NVD_WINDOW_SECONDS = 30


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


def _extract_cvss_from_metrics(metrics: dict) -> tuple[float, str] | None:
    """
    Returns (base_score, severity) from NVD metrics, preferring v3.1 > v3.0 > v2.
    Returns None if no usable metric is present.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        if score is None:
            continue
        raw_sev = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        if not raw_sev:
            # v2 often omits baseSeverity — derive it from the score.
            score_f = float(score)
            if score_f >= 9.0:
                raw_sev = "critical"
            elif score_f >= 7.0:
                raw_sev = "high"
            elif score_f >= 4.0:
                raw_sev = "medium"
            elif score_f > 0:
                raw_sev = "low"
            else:
                raw_sev = "none"
        return float(score), raw_sev.lower()
    return None


def _fetch_nvd_cvss_batch(cve_ids: list[str]) -> dict[str, tuple[float, str]]:
    """
    Queries NVD 2.0 for CVSS base score + severity for each CVE id.

    Rate limits are respected automatically:
      - Without API key: 4 requests per 30-second window (NVD allows 5; -1 margin).
      - With API key   : 40 requests per 30-second window (NVD allows 50; -10 margin).

    On HTTP 429 the request is retried once after waiting for the next window boundary.

    Returns {cve_id: (score, severity)} only for CVEs where data was obtained.
    Private function — public API is run_sync() and lookup_cves().
    """
    if not cve_ids:
        return {}

    has_key = bool(settings.nvd_api_key)
    rate_limit = _NVD_RATE_WITH_KEY if has_key else _NVD_RATE_NO_KEY
    headers = {"apiKey": settings.nvd_api_key} if has_key else {}

    out: dict[str, tuple[float, str]] = {}
    window_start = time.monotonic()
    requests_in_window = 0

    for cve_id in cve_ids:
        # Enforce rate limit: if we've hit the window quota, sleep until the window resets.
        if requests_in_window >= rate_limit:
            elapsed = time.monotonic() - window_start
            wait = _NVD_WINDOW_SECONDS - elapsed
            if wait > 0:
                logger.debug("NVD CVSS: rate-limit pause %.1fs after %d requests", wait, requests_in_window)
                time.sleep(wait)
            window_start = time.monotonic()
            requests_in_window = 0

        nvd_params = {"cveId": cve_id}

        try:
            resp = httpx.get(
                settings.nvd_api_base,
                params=nvd_params,
                headers=headers,
                timeout=15.0,
                follow_redirects=True,
            )
            requests_in_window += 1

            if resp.status_code == 429:
                # One retry: wait for a full window then try again.
                logger.warning("NVD CVSS: 429 for %s — backing off %ds", cve_id, _NVD_WINDOW_SECONDS)
                time.sleep(_NVD_WINDOW_SECONDS)
                window_start = time.monotonic()
                requests_in_window = 0
                resp = httpx.get(
                    settings.nvd_api_base,
                    params=nvd_params,
                    headers=headers,
                    timeout=15.0,
                    follow_redirects=True,
                )
                requests_in_window += 1

            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.warning("NVD CVSS: HTTP %s for %s — skipping", exc.response.status_code, cve_id)
            continue
        except Exception as exc:
            logger.warning("NVD CVSS: request error for %s: %s — skipping", cve_id, exc)
            continue

        try:
            data = resp.json()
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                continue
            metrics = vulns[0]["cve"].get("metrics", {})
            result = _extract_cvss_from_metrics(metrics)
            if result is not None:
                out[cve_id] = result
        except Exception as exc:
            logger.warning("NVD CVSS: parse error for %s: %s — skipping", cve_id, exc)
            continue

    logger.info(
        "NVD CVSS enrichment: %d/%d CVEs resolved",
        len(out),
        len(cve_ids),
    )
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

    # ── NVD CVSS enrichment for KEV CVEs ─────────────────────────────────────
    # Only enrich CVEs that are in KEV and currently lack a CVSS score. This
    # avoids hammering NVD for the ~250k EPSS-only rows (out of scope for now).
    # We query the DB so the list stays accurate even across incremental syncs
    # (e.g. a second run that finds scores already filled in by cpe_intel.py).
    kev_ids = list(kev.keys())
    if kev_ids:
        try:
            res = (
                supabase.table("cve_intel")
                .select("cve_id")
                .in_("cve_id", kev_ids)
                .is_("cvss_score", "null")
                .execute()
            )
            missing_cvss = [r["cve_id"] for r in (res.data or [])]
        except Exception:
            logger.exception("NVD CVSS: failed to query null-score KEV CVEs; skipping enrichment")
            missing_cvss = []

        if missing_cvss:
            logger.info("NVD CVSS: enriching %d KEV CVEs with missing scores", len(missing_cvss))
            cvss_data = _fetch_nvd_cvss_batch(missing_cvss)
            if cvss_data:
                now = datetime.now(timezone.utc).isoformat()
                cvss_rows = [
                    {
                        "cve_id": cve_id,
                        "cvss_score": score,
                        "cvss_severity": severity,
                        "updated_at": now,
                    }
                    for cve_id, (score, severity) in cvss_data.items()
                ]
                _batch_upsert(cvss_rows)
                logger.info("NVD CVSS: wrote scores for %d CVEs", len(cvss_rows))

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
