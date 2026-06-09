"""Web search for agent intelligence gathering — Tavily API with graceful fallback."""

import logging
import httpx
from backend.core.config import settings

logger = logging.getLogger(__name__)

_TAVILY_URL = "https://api.tavily.com/search"
_TIMEOUT = 15.0


def web_search(query: str, max_results: int = 5) -> dict:
    """
    Searches the web for security intelligence.
    Uses Tavily if configured; returns an empty result set if no key is available.
    """
    if not settings.tavily_api_key:
        logger.debug("web_search: tavily_api_key not configured — skipping search")
        return {
            "query": query,
            "results": [],
            "note": "Web search disabled — configure TAVILY_API_KEY to enable",
        }

    try:
        resp = httpx.post(
            _TAVILY_URL,
            json={
                "api_key": settings.tavily_api_key,
                "query": query,
                "search_depth": "basic",
                "max_results": max_results,
                "include_answer": True,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "query": query,
            "answer": data.get("answer"),
            "results": [
                {
                    "title": r.get("title"),
                    "url": r.get("url"),
                    "snippet": r.get("content", "")[:400],
                    "score": r.get("score"),
                }
                for r in data.get("results", [])
            ],
        }
    except httpx.HTTPStatusError as e:
        logger.warning("web_search: Tavily API error %s", e.response.status_code)
        return {"query": query, "results": [], "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        logger.warning("web_search: %s", e)
        return {"query": query, "results": [], "error": str(e)}
