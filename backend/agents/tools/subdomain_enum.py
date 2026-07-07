"""Subdomain enumeration — Certificate Transparency logs via crt.sh."""

import logging
import httpx
from backend.core.config import settings

logger = logging.getLogger(__name__)


def enumerate_subdomains(domain: str) -> dict:
    """
    Discovers subdomains via Certificate Transparency logs (crt.sh).
    Returns unique subdomains with their cert issuance dates.
    """
    result = {
        "domain": domain,
        "subdomains": [],
        "count": 0,
        "issues": [],
    }

    url = settings.discovery_crtsh_url
    params = {"q": f"%.{domain}", "output": "json"}

    for attempt in range(settings.discovery_crtsh_retries + 1):
        try:
            resp = httpx.get(
                url,
                params=params,
                timeout=settings.discovery_timeout_seconds,
                follow_redirects=True,
            )
            if resp.status_code != 200:
                result["issues"].append(f"crt.sh returned HTTP {resp.status_code}")
                return result

            entries = resp.json()
            seen: set[str] = set()
            for e in entries:
                for name in (e.get("name_value") or "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name and name != domain and name.endswith(f".{domain}") and name not in seen:
                        seen.add(name)
                        result["subdomains"].append({
                            "name": name,
                            "logged_at": e.get("entry_timestamp"),
                            "issuer": e.get("issuer_name"),
                        })

            result["count"] = len(result["subdomains"])
            if result["count"] > 20:
                result["issues"].append(
                    f"Large number of subdomains ({result['count']}) — review for forgotten or dangling entries"
                )
            return result

        except httpx.TimeoutException:
            if attempt < settings.discovery_crtsh_retries:
                continue
            result["issues"].append("crt.sh timed out — no subdomain data available")
            return result
        except Exception as e:
            result["issues"].append(f"crt.sh error: {e}")
            return result

    return result
