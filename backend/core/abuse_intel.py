"""
abuse.ch IOC feed integrations (ThreatFox + URLhaus).

Queries free abuse.ch APIs to check if org assets (IPs, domains) are listed as indicators
of compromise (C2, malware, malicious URLs). No auth required, public data.

- ThreatFox: https://threatfox-api.abuse.ch/api/ — searches for IOCs by IP/domain
- URLhaus: https://urlhaus-api.abuse.ch/ — checks if domains host malicious URLs

Rate limiting: Neither API documents rate limits; we use 10s timeouts and graceful error handling.
"""

import logging
import httpx


logger = logging.getLogger(__name__)

_THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
_TIMEOUT_SECONDS = 10.0


def check_threatfox(ioc: str) -> dict:
    """
    Search ThreatFox IOC database for an IP or domain.

    Args:
        ioc: IP address or domain to search

    Returns:
        {
            "found": bool,
            "threats": [
                {
                    "ioc_type": "ip:port" | "domain" | ...,
                    "threat_type": "c2" | "malware" | ...,
                    "malware": "ransomware_name" | None,
                    "confidence_level": 0-100,
                    "first_seen": "YYYY-MM-DD",
                    "reference": "https://...",
                    "source": "threatfox",
                    ...
                }
            ]
        }

    On API error, returns {"found": False, "threats": []} with logged warning.
    """
    if not ioc or not ioc.strip():
        return {"found": False, "threats": []}

    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            resp = client.post(
                _THREATFOX_API,
                json={"query": "search_ioc", "search_term": ioc.strip()}
            )
        resp.raise_for_status()
        data = resp.json()

        # ThreatFox returns query_status: "ok" | "no_result"
        if data.get("query_status") == "ok" and data.get("data"):
            threats = []
            for ioc_record in data["data"]:
                threats.append({
                    "ioc_type": ioc_record.get("ioc_type"),
                    "threat_type": ioc_record.get("threat_type"),
                    "malware": ioc_record.get("malware"),
                    "malware_alias": ioc_record.get("malware_alias"),
                    "confidence_level": ioc_record.get("confidence_level"),
                    "first_seen": ioc_record.get("first_seen"),
                    "last_seen": ioc_record.get("last_seen"),
                    "reference": ioc_record.get("reference"),
                    "tags": ioc_record.get("tags"),
                    "source": "threatfox",
                })
            return {"found": True, "threats": threats}

        return {"found": False, "threats": []}

    except httpx.HTTPStatusError as e:
        logger.warning(f"threatfox: HTTP {e.response.status_code} for {ioc}")
        return {"found": False, "threats": []}
    except Exception as e:
        logger.warning(f"threatfox {ioc}: {type(e).__name__}: {e}")
        return {"found": False, "threats": []}


def check_urlhaus(host: str) -> dict:
    """
    Check URLhaus for malicious URLs hosted on a domain/IP.

    Args:
        host: Domain name or IP address to check

    Returns:
        {
            "found": bool,
            "urls": [
                {
                    "url": "https://...",
                    "url_status": "online" | "offline" | "unknown",
                    "threat": "malware" | "phishing" | ...,
                    "date_added": "YYYY-MM-DD",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/...",
                    "source": "urlhaus",
                    ...
                }
            ]
        }

    On API error, returns {"found": False, "urls": []} with logged warning.
    """
    if not host or not host.strip():
        return {"found": False, "urls": []}

    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            resp = client.post(
                f"{_URLHAUS_API}host/",
                data={"host": host.strip()}
            )
        resp.raise_for_status()
        data = resp.json()

        # URLhaus returns query_status: "islisted" | "no_results"
        if data.get("query_status") == "islisted" and data.get("urls"):
            urls = []
            for url_record in data["urls"]:
                urls.append({
                    "url": url_record.get("url"),
                    "url_status": url_record.get("url_status"),
                    "threat": url_record.get("threat"),
                    "tags": url_record.get("tags"),
                    "date_added": url_record.get("date_added"),
                    "urlhaus_link": url_record.get("urlhaus_link"),
                    "source": "urlhaus",
                })
            return {"found": True, "urls": urls}

        return {"found": False, "urls": []}

    except httpx.HTTPStatusError as e:
        logger.warning(f"urlhaus: HTTP {e.response.status_code} for {host}")
        return {"found": False, "urls": []}
    except Exception as e:
        logger.warning(f"urlhaus {host}: {type(e).__name__}: {e}")
        return {"found": False, "urls": []}
