"""
Analyst team — specialist analysts that classify findings in parallel.

TradingAgents runs a team of specialist analysts (fundamental / sentiment / news / technical) in
parallel, each an expert on one slice of the data; their outputs are then synthesized. Our analogue:
instead of one generalist grinding through every raw finding in a single prompt, we route each finding
to a domain specialist — web/appsec, network/infra, or TLS/crypto — and run them concurrently. Each
specialist reasons with less, more relevant context (sharper severity calls) and the calls run in
parallel (lower latency on big scans).

`classify_domain` is a pure keyword router (unit-tested). `SpecialistAnalyst` is a one-domain analyst;
`AnalystAgent` owns the fan-out/merge. Output is identical to the old single-call analyst
(AnalyzedFinding dicts), so everything downstream is unchanged.
"""

from backend.agents.base import BaseAgent
from backend.agents.state import RawFinding

# Domains, most specific first — classify_domain checks TLS before web before network.
WEB = "web"
NETWORK = "network"
TLS = "tls"
GENERIC = "generic"

# Keyword routers over "<tool> <template_id> <name>". Order of the checks matters (see classify_domain).
_TLS_KW = ("ssl", "tls", "cert", "cipher", "x509", "heartbleed", "poodle", "rc4", "sweet32", "starttls")
_WEB_KW = (
    "http", "html", "xss", "csrf", "cookie", "header", "cors", "clickjack", "sqli", "sql-injection",
    "lfi", "rfi", "ssrf", "web", "php", "wordpress", "apache", "nginx", "iis", "redirect", "jwt",
    "api", "graphql", "openapi", "swagger",
)
_NETWORK_KW = (
    "port", "smb", "rdp", "ssh", "ftp", "telnet", "dns", "snmp", "ntp", "smtp", "imap", "pop3",
    "service", "banner", "rpc", "ldap", "kerberos", "mysql", "postgres", "redis", "mongodb",
)


def classify_domain(raw: RawFinding | dict) -> str:
    """Route a raw finding to a specialist domain by keyword. Pure and deterministic."""
    if isinstance(raw, RawFinding):
        tool, template_id, name = raw.tool, (raw.template_id or ""), raw.name
    else:
        tool = raw.get("tool", "")
        template_id = raw.get("template_id") or ""
        name = raw.get("name", "")
    text = f"{tool} {template_id} {name}".lower()

    if any(k in text for k in _TLS_KW):
        return TLS
    if tool == "zap" or any(k in text for k in _WEB_KW):
        return WEB
    if tool == "nmap" or any(k in text for k in _NETWORK_KW):
        return NETWORK
    return GENERIC


_SCHEMA = """For each finding, output a JSON object matching this schema:
{
  "id": "<sha256 fingerprint: sha256(asset_id:tool:template_id_or_name)>",
  "title": "<concise title>",
  "description": "<clear technical description, ONE sentence>",
  "severity": "<critical|high|medium|low|info>",
  "cvss_score": <float or null>,
  "cve_ids": ["CVE-XXXX-XXXXX"],
  "confidence": <0.0-1.0>,
  "rationale": "<why you assigned this severity and confidence, ONE sentence>"
}

Do NOT guess CVE numbers — only include cve_ids the scanner explicitly reported; leave the array
empty otherwise (CVE enrichment happens downstream from a trusted database).
Respond ONLY with a valid JSON array. No markdown, no prose outside the JSON."""

# Per-domain expert framing. Each specialist sees only its slice, so the focus sharpens severity.
SPECIALIST_FOCUS = {
    WEB: (
        "You are a senior web application security analyst. These findings are HTTP/web/API issues. "
        "Weigh real exploitability: reflected/stored XSS, auth bypass, SSRF and injection are serious; "
        "missing security headers and unconfirmed nmap http-* 'potential' scripts are usually low/info."
    ),
    NETWORK: (
        "You are a senior network/infrastructure security analyst. These findings are exposed ports, "
        "services and protocol issues. Weigh exposure and authentication: an exposed admin/database "
        "service or weak/legacy protocol is serious; a benign open port with no known weakness is low."
    ),
    TLS: (
        "You are a senior cryptography/TLS analyst. These findings are certificate, cipher and TLS "
        "configuration issues. Weigh practical risk: expired/invalid certs and exploitable cipher flaws "
        "matter; cosmetic or theoretical weaknesses on internal services are low."
    ),
    GENERIC: (
        "You are a senior vulnerability analyst. Classify each finding by real-world severity and how "
        "confident you are that it is a true, exploitable issue."
    ),
}


def system_prompt_for(domain: str) -> str:
    return f"{SPECIALIST_FOCUS.get(domain, SPECIALIST_FOCUS[GENERIC])}\n\n{_SCHEMA}"


class SpecialistAnalyst(BaseAgent):
    """One-domain analyst. A fresh instance per domain so parallel runs share no mutable state
    (token accounting stays correct). Uses the analyst model (llm_analyst_model)."""

    agent_type = "analyst"

    def run(self, state):  # not used as a pipeline agent; AnalystAgent drives analyze()
        raise NotImplementedError("SpecialistAnalyst is invoked via analyze(), not run()")

    def analyze(self, asset_id: str, asset_host: str, domain: str, findings: list[RawFinding]):
        """Returns (raw_analyzed_dicts, tokens_used) for one domain's findings."""
        import json

        findings_json = json.dumps([f.model_dump() for f in findings], separators=(",", ":"))
        user_content = (
            f"Asset ID: {asset_id}\nAsset host: {asset_host}\nDomain: {domain}\n\n"
            f"Raw findings:\n{findings_json}"
        )
        raw, tokens = self.call_llm_json(system_prompt_for(domain), user_content, max_tokens=4096)
        if not isinstance(raw, list):
            raw = [raw]
        return raw, tokens
