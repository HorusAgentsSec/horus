"""
Jira Cloud ticketing — the response half of SOAR.

Turns a Horus finding into a Jira issue via the REST v3 API. Configured per org as an
`integrations` row (type="jira"):

  {"base_url": "https://acme.atlassian.net", "user_email": "bot@acme.com",
   "api_token": "<Atlassian API token>", "project_key": "SEC"}

Every failure is normalized into JiraError with a message that is safe and useful to show
the user (no secrets, no raw tracebacks): wrong credentials, bad base URL, missing project,
network unreachable — each tells the admin what to fix.
"""

import json
import logging

import httpx

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 15.0
REQUIRED_KEYS = ("base_url", "user_email", "api_token", "project_key")

# Keys from finding.raw_data worth surfacing in the ticket, in display order.
_EVIDENCE_KEYS = (
    "matched_at", "url", "template_id", "evidence", "extracted_results",
    "exploitability", "threat_context", "verdict", "verdict_rationale",
)
_EVIDENCE_MAX_CHARS = 2000


class JiraError(Exception):
    """Actionable Jira failure — str(e) is safe to return to the client."""


def validate_config(config: dict) -> None:
    missing = [k for k in REQUIRED_KEYS if not (config or {}).get(k)]
    if missing:
        raise JiraError(
            "Jira integration is missing required fields: " + ", ".join(missing)
        )


def _base_url(config: dict) -> str:
    return str(config["base_url"]).rstrip("/")


def _error_detail(resp: httpx.Response) -> str:
    """Extract Jira's human-readable error messages from an error response body."""
    try:
        data = resp.json()
        messages = list(data.get("errorMessages") or [])
        messages += [f"{k}: {v}" for k, v in (data.get("errors") or {}).items()]
        if messages:
            return "; ".join(messages)
    except Exception:
        pass
    return resp.text[:200] or "no detail provided"


def _jira_request(config: dict, method: str, path: str, json_body: dict | None = None) -> dict:
    """One Jira REST v3 call with every failure mode mapped to an actionable JiraError."""
    url = f"{_base_url(config)}/rest/api/3{path}"
    try:
        resp = httpx.request(
            method,
            url,
            json=json_body,
            auth=(config["user_email"], config["api_token"]),
            headers={"Accept": "application/json"},
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.HTTPError as e:
        raise JiraError(
            f"could not reach Jira at {_base_url(config)} ({e.__class__.__name__}) — "
            "check the base URL and network access"
        ) from e

    if resp.status_code in (401, 403):
        raise JiraError(
            f"Jira rejected the credentials ({resp.status_code}) — "
            "check the user email and API token, and that the account can access the project"
        )
    if resp.status_code == 404:
        raise JiraError(
            "Jira returned 404 — check the base URL (it should look like "
            "https://yourcompany.atlassian.net) and the project key"
        )
    if resp.status_code >= 400:
        raise JiraError(f"Jira error {resp.status_code}: {_error_detail(resp)}")
    try:
        return resp.json() if resp.content else {}
    except ValueError:
        raise JiraError("Jira returned a non-JSON response — check the base URL")


def test_connection(config: dict) -> dict:
    """GET /myself with the stored credentials. Returns who Jira thinks we are."""
    validate_config(config)
    me = _jira_request(config, "GET", "/myself")
    return {
        "ok": True,
        "account": me.get("displayName") or me.get("emailAddress") or "unknown account",
    }


# ── Issue payload construction ───────────────────────────────────────────────
# Jira Cloud REST v3 requires descriptions in Atlassian Document Format (ADF).

def _adf_paragraph(text: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _adf_code_block(text: str) -> dict:
    return {"type": "codeBlock", "attrs": {"language": "json"},
            "content": [{"type": "text", "text": text}]}


def _evidence_summary(raw_data: dict) -> str:
    """Compact, truncated JSON of the interesting evidence keys (never the whole blob)."""
    picked = {k: raw_data[k] for k in _EVIDENCE_KEYS if raw_data.get(k)}
    if not picked:
        return ""
    text = json.dumps(picked, indent=2, default=str, ensure_ascii=False)
    if len(text) > _EVIDENCE_MAX_CHARS:
        text = text[:_EVIDENCE_MAX_CHARS] + "\n… (truncated)"
    return text


def build_issue_payload(finding: dict, project_key: str) -> dict:
    """Map a finding (with optional joined assets(name, host)) to a Jira create-issue body."""
    asset = finding.get("assets") or {}
    asset_label = asset.get("name") or asset.get("host") or "unknown asset"
    if asset.get("host") and asset.get("name") and asset["host"] != asset["name"]:
        asset_label = f"{asset['name']} ({asset['host']})"
    severity = (finding.get("severity") or "info").upper()

    summary = f"[Horus][{severity}] {finding.get('title', 'Security finding')}"[:254]

    facts = [f"Severity: {severity}", f"Asset: {asset_label}"]
    if finding.get("cvss_score") is not None:
        facts.append(f"CVSS: {finding['cvss_score']}")
    if finding.get("cve_ids"):
        facts.append("CVEs: " + ", ".join(finding["cve_ids"]))
    if finding.get("first_seen_at"):
        facts.append(f"First seen: {finding['first_seen_at']}")

    content: list[dict] = [_adf_paragraph(" · ".join(facts))]
    if finding.get("description"):
        content.append(_adf_paragraph(str(finding["description"])[:3000]))
    evidence = _evidence_summary(finding.get("raw_data") or {})
    if evidence:
        content.append(_adf_paragraph("Evidence (from Horus):"))
        content.append(_adf_code_block(evidence))
    content.append(_adf_paragraph("Created automatically by Horus."))

    return {
        "fields": {
            "project": {"key": project_key},
            "issuetype": {"name": "Task"},
            "summary": summary,
            "description": {"type": "doc", "version": 1, "content": content},
            "labels": ["horus", f"severity-{(finding.get('severity') or 'info')}"],
        }
    }


def create_issue(config: dict, finding: dict) -> dict:
    """Create the Jira issue for a finding. Returns {"ticket_key", "ticket_url"}."""
    validate_config(config)
    payload = build_issue_payload(finding, config["project_key"])
    data = _jira_request(config, "POST", "/issue", json_body=payload)
    key = data.get("key")
    if not key:
        raise JiraError("Jira accepted the request but returned no issue key")
    return {"ticket_key": key, "ticket_url": f"{_base_url(config)}/browse/{key}"}
