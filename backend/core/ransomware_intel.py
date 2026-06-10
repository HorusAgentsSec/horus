"""
Ransomware.live deep web intelligence integration.

Queries the free Ransomware.live API (https://api.ransomware.live) for recent
ransomware victim disclosures, checks if any match org assets by domain, and
correlates matches to findings. No auth required, public data.

Rate limiting: The API has no documented rate limit; we use 15s timeout and
graceful error handling.
"""

import logging
import hashlib
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.core.config import settings

logger = logging.getLogger(__name__)

_RANSOMWARE_API_BASE = "https://api.ransomware.live"
_TIMEOUT_SECONDS = 15.0


def fetch_recent_victims(hours: int = 48) -> list[dict]:
    """
    Fetch recent victims from Ransomware.live.

    Tries the /recentvictims endpoint first (if available), falls back to
    /victims if that fails.

    Returns a list of raw victim dicts from the API, or [] on failure.
    """
    urls_to_try = [
        f"{_RANSOMWARE_API_BASE}/recentvictims",
        f"{_RANSOMWARE_API_BASE}/victims",
    ]

    for url in urls_to_try:
        try:
            with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
                resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                logger.info(f"ransomware.live: fetched {len(data)} victims from {url.split('/')[-1]}")
                return data
        except httpx.HTTPStatusError as e:
            logger.warning(f"ransomware.live {url}: HTTP {e.response.status_code}")
            continue
        except Exception as e:
            logger.warning(f"ransomware.live {url}: {type(e).__name__}: {e}")
            continue

    logger.warning("ransomware.live: all endpoints failed, returning empty list")
    return []


def _normalize_domain(domain: str) -> str:
    """
    Normalize a domain for comparison: strip www, lowercase, no trailing dot.
    """
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    d = d.rstrip(".")
    return d


def _extract_domain(url_or_host: str) -> str:
    """
    Extract the domain from a URL, hostname, or email.
    Removes port, subdomains (keeps only the root domain + TLD).
    Returns normalized domain.
    """
    s = (url_or_host or "").strip().lower()
    if not s:
        return ""

    # If it looks like a URL, parse it
    if "://" in s:
        try:
            parsed = urlparse(s)
            s = parsed.netloc or parsed.path
        except Exception:
            pass

    # Remove port
    if ":" in s:
        s = s.split(":")[0]

    # Basic domain extraction: keep the rightmost 2 parts (domain.tld)
    # This is a simplification but covers the common case
    # e.g., "www.example.com" -> "example.com", "mail.internal.example.com" -> "example.com"
    parts = s.split(".")
    if len(parts) >= 2:
        # Keep the last 2 parts (root domain + TLD)
        # This is a heuristic; better would be against a public suffix list
        s = ".".join(parts[-2:])

    return _normalize_domain(s)


def check_domain(domain: str) -> list[dict]:
    """
    Check if a domain (or hostname) has been mentioned in ransomware.live victims.

    Fetches the victims list, normalizes the query domain, and returns all matches.
    Matching is done against the victim's website, post_title, and group_name fields.

    Returns a list of normalized victim dicts.
    """
    if not domain or not domain.strip():
        return []

    query_domain = _extract_domain(domain)
    if not query_domain:
        return []

    victims = fetch_recent_victims()
    matches = []

    for victim in victims:
        try:
            # Check multiple fields for the domain
            victim_site = (victim.get("website") or "").lower()
            victim_title = (victim.get("post_title") or "").lower()
            victim_group = (victim.get("group_name") or "").lower()
            victim_name = (victim.get("victim") or "").lower()

            # Extract domain from the website field if it's a URL
            site_domain = _extract_domain(victim_site) if victim_site else ""

            # Match if query_domain appears in any field or if site_domain matches
            if (query_domain in site_domain or
                query_domain in victim_title or
                query_domain in victim_group or
                query_domain in victim_name):
                matches.append(victim)
        except Exception as e:
            logger.debug(f"ransomware.live: error checking victim {victim.get('id')}: {e}")
            continue

    if matches:
        logger.info(f"ransomware.live: found {len(matches)} matches for domain {query_domain}")

    return matches


def normalize_victim(raw: dict) -> dict:
    """
    Normalize a raw ransomware.live victim dict to canonical form.

    Returns a dict with stable keys suitable for storage in findings.raw_data.
    """
    return {
        "title": (raw.get("post_title") or "").strip(),
        "group": (raw.get("group_name") or "").strip(),
        "victim": (raw.get("victim") or "").strip(),
        "discovered_at": (raw.get("discovered") or "").strip(),
        "leak_url": (raw.get("url") or "").strip(),
        "description": (raw.get("description") or "").strip(),
        "website": (raw.get("website") or "").strip(),
        "country": (raw.get("country") or "").strip(),
        "source": "ransomware.live",
    }
