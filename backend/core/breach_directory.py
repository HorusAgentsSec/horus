"""
BreachDirectory.org API client for credential exposure checking.

Queries the BreachDirectory API for email addresses or domains that appear in
known data breaches. Requires an API key from breachdirectory.org (free tier available).

API endpoint: https://breachdirectory.p.rapidapi.com/?func=auto&term=<email_or_domain>
Headers: X-RapidAPI-Key, X-RapidAPI-Host: breachdirectory.p.rapidapi.com
Rate limit: 50 req/day on free tier.
"""

import logging

import httpx

logger = logging.getLogger(__name__)

# BreachDirectory RapidAPI configuration
_BREACH_DIRECTORY_HOST = "https://breachdirectory.p.rapidapi.com"
_BREACH_DIRECTORY_RAPID_HOST = "breachdirectory.p.rapidapi.com"
_TIMEOUT_SECONDS = 10


def check_email(email: str, api_key: str) -> dict:
    """
    Check if an email appears in any known breaches on BreachDirectory.

    Args:
        email: Email address to check (e.g., user@example.com)
        api_key: BreachDirectory API key (X-RapidAPI-Key)

    Returns:
        {
            "found": bool,
            "sources": [
                {
                    "name": str,         # Breach/source name
                    "date": str|null,    # Breach date if known (YYYY-MM-DD)
                    "count": int,        # Number of entries
                }
            ],
            "sha1_hash": str|None,       # SHA1 of the email if available
        }

    Raises:
        ValueError: If api_key is not configured
        httpx.HTTPError: On network/HTTP errors
    """
    if not api_key or not api_key.strip():
        raise ValueError("BreachDirectory API key not configured")

    return _check_term(email, api_key)


def check_domain(domain: str, api_key: str) -> dict:
    """
    Check if a domain appears in any known breaches on BreachDirectory.

    Args:
        domain: Domain to check (e.g., example.com)
        api_key: BreachDirectory API key (X-RapidAPI-Key)

    Returns:
        Same shape as check_email(). BreachDirectory supports domain queries
        to find all email addresses under a domain.

    Raises:
        ValueError: If api_key is not configured
        httpx.HTTPError: On network/HTTP errors
    """
    if not api_key or not api_key.strip():
        raise ValueError("BreachDirectory API key not configured")

    return _check_term(domain, api_key)


def _check_term(term: str, api_key: str) -> dict:
    """
    Internal: Query BreachDirectory for a term (email or domain).

    The BreachDirectory API returns results in the shape:
    {
        "found": bool,
        "result": [
            {
                "sha1": str,
                "sources": [
                    {
                        "name": str,
                        "date": str,
                        "entries": int,
                    }
                ]
            }
        ]
    }

    We normalize to a consistent shape for the frontend.
    """
    url = f"{_BREACH_DIRECTORY_HOST}/"
    params = {"func": "auto", "term": term}
    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": _BREACH_DIRECTORY_RAPID_HOST,
    }

    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            # term goes through params so httpx url-encodes it; interpolating it into
            # the URL let an email/domain with & = ? # break the query or inject params.
            resp = client.get(url, params=params, headers=headers)

        if resp.status_code == 404:
            # Not found in any breach
            return {"found": False, "sources": [], "sha1_hash": None}

        resp.raise_for_status()
        data = resp.json()

        # Normalize response
        found = data.get("found", False)
        sha1_hash = None
        sources = []

        if found and isinstance(data.get("result"), list):
            for entry in data["result"]:
                sha1_hash = entry.get("sha1")
                for src in entry.get("sources", []):
                    sources.append({
                        "name": src.get("name", "Unknown"),
                        "date": src.get("date"),
                        "count": src.get("entries", 0),
                    })

        return {
            "found": found,
            "sources": sources,
            "sha1_hash": sha1_hash,
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            logger.error("BreachDirectory: invalid API key")
            raise ValueError("BreachDirectory API key is invalid or expired")
        elif e.response.status_code == 429:
            logger.warning("BreachDirectory: rate limit exceeded for term %s", term)
            raise ValueError("BreachDirectory rate limit exceeded; try again later")
        else:
            logger.warning("BreachDirectory request failed for %s: %s", term, e)
            raise
    except Exception as e:
        logger.warning("BreachDirectory request error for %s: %s", term, e)
        raise
