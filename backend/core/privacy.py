"""
Privacy posture — what the current deployment actually does with customer data.

Turns the raw config (llm_enabled, redaction_enabled, the LLM endpoint) into one honest, surfaceable
verdict: does any data leave the perimeter, and if so, in what form. Shown in the UI as a trust
signal and used in sales ("your deployment runs in Sovereign mode — nothing leaves your network").

Pure (reads settings); unit-tested.
"""

import ipaddress
from urllib.parse import urlparse

from backend.core.config import settings

# mode -> (label, whether data leaves the perimeter, one-line description)
_MODES = {
    "no_cloud": (
        "Sovereign (no-cloud)", False,
        "Fully deterministic pipeline — zero LLM calls. No customer data ever leaves the perimeter.",
    ),
    "byo_local": (
        "Sovereign (local model)", False,
        "LLM runs on a local/in-VPC endpoint. Findings are analyzed by AI without data leaving your network.",
    ),
    "cloud_redacted": (
        "Private (cloud + redaction)", True,
        "A cloud model is used, but hostnames, IPs and emails are pseudonymized before any prompt leaves — the model never sees them in clear.",
    ),
    "cloud": (
        "Standard (cloud)", True,
        "A cloud model is used and prompts are sent without redaction. Highest model fidelity, lowest privacy.",
    ),
}


def is_local_endpoint(base_url: str | None) -> bool:
    """True if the LLM endpoint is loopback / private / internal (i.e. in the customer's perimeter)."""
    host = (urlparse(base_url or "").hostname or "").lower()
    if not host:
        return False
    if host in ("localhost", "host.docker.internal"):
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def current_mode() -> str:
    if not settings.llm_enabled:
        return "no_cloud"
    if is_local_endpoint(settings.llm_base_url):
        return "byo_local"
    if settings.redaction_enabled:
        return "cloud_redacted"
    return "cloud"


def privacy_status() -> dict:
    """The deployment's data-privacy posture, for the UI and API."""
    mode = current_mode()
    label, leaves, description = _MODES[mode]
    host = (urlparse(settings.llm_base_url or "").hostname or "") if settings.llm_enabled else None
    return {
        "mode": mode,
        "label": label,
        "data_leaves_perimeter": leaves,
        "description": description,
        "llm_enabled": settings.llm_enabled,
        "redaction_enabled": settings.redaction_enabled,
        "llm_endpoint": host,  # host only — never the API key
    }
