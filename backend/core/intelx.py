"""
IntelligenceX dark web search client.

Searches for mentions of domains, IPs, and emails across dark web sources
(Tor, I2P, Pastebin, leaks, etc.) via the IntelligenceX API.
https://intelx.io/api

Two-step search flow:
1. POST /intelligent/search with term → get search_id
2. Poll GET /intelligent/search/result?id=<search_id> until status=2 (complete)

Auth: header x-key: <API_KEY>. Free tier: ~10 searches/month.
"""

import logging
import time
from typing import Any

import httpx

from backend.core.config import settings

logger = logging.getLogger(__name__)

_INTELX_BASE = "https://2.intelx.io"
_POLL_INTERVAL = 2  # seconds
_MAX_POLLS = 3
_REQUEST_TIMEOUT = 10  # per request
_TOTAL_TIMEOUT = 30  # max time for entire search


def search(term: str, api_key: str, max_results: int = 10) -> list[dict]:
    """
    Search IntelligenceX for mentions of a term across dark web sources.

    Args:
        term: Domain, IP, email, or any search term
        api_key: IntelligenceX API key
        max_results: Max records to return

    Returns:
        List of normalized records: {name, date, bucket, source: "intelx"}
        Returns [] on error or timeout.

    Raises:
        ValueError: If API key is not configured
    """
    if not api_key:
        raise ValueError("IntelligenceX API key not configured")

    headers = {"x-key": api_key}
    start_time = time.time()

    # Step 1: Initiate search
    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{_INTELX_BASE}/intelligent/search",
                json={
                    "term": term,
                    "maxresults": max_results,
                    "media": 0,
                    "target": 0,
                    "timeout": 10,
                    "datefrom": "",
                    "dateto": "",
                    "sort": 2,
                    "terminate": [],
                },
                headers=headers,
            )
        if resp.status_code == 401:
            logger.error("IntelligenceX: invalid API key")
            return []
        if resp.status_code == 402:
            logger.warning("IntelligenceX: rate limit or quota exceeded")
            return []
        resp.raise_for_status()
        data = resp.json()
        search_id = data.get("id")
        if not search_id:
            logger.warning("IntelligenceX: no search_id returned")
            return []
    except httpx.HTTPStatusError as e:
        logger.warning("IntelligenceX search initiation failed: %s", e)
        return []
    except Exception as e:
        logger.warning("IntelligenceX request error: %s", e)
        return []

    # Step 2: Poll for results until status=2 (complete)
    records = []
    for poll_count in range(_MAX_POLLS):
        if time.time() - start_time > _TOTAL_TIMEOUT:
            logger.warning("IntelligenceX: total timeout after %d polls", poll_count)
            break

        try:
            with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
                resp = client.get(
                    f"{_INTELX_BASE}/intelligent/search/result",
                    params={"id": search_id, "limit": max_results, "offset": 0},
                    headers=headers,
                )
            if resp.status_code == 401:
                logger.error("IntelligenceX: invalid API key during polling")
                return records
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status")
            raw_records = data.get("records", [])

            # Normalize records
            for r in raw_records:
                records.append(
                    {
                        "name": r.get("name", ""),
                        "date": r.get("date", ""),
                        "bucket": r.get("bucket", ""),
                        "source": "intelx",
                    }
                )

            # Status 2 = complete, 1 = more results available
            if status == 2:
                break
        except httpx.HTTPStatusError as e:
            logger.warning("IntelligenceX polling failed: %s", e)
            break
        except Exception as e:
            logger.warning("IntelligenceX poll error: %s", e)
            break

        # Wait before next poll (except on last iteration)
        if poll_count < _MAX_POLLS - 1:
            time.sleep(_POLL_INTERVAL)

    logger.info("IntelligenceX: found %d records for term '%s'", len(records), term)
    return records


def is_darkweb_result(record: dict) -> bool:
    """
    Check if a record is from dark web sources.

    Dark web buckets include: "darkweb", "leaks", "pastes", "i2p", "tor", etc.
    """
    bucket = (record.get("bucket") or "").lower()
    darkweb_keywords = ["darkweb", "leaks", "pastes", "i2p", "tor", "onion"]
    return any(kw in bucket for kw in darkweb_keywords)
