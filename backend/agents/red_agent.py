"""
RedAgent — adversarial recon agent.

Thinks like an external attacker. For every asset in an org it uses tool-calling
to probe attack surface that automated scanners typically miss: DNS misconfigs,
exposed sensitive paths, weak TLS, missing headers, subdomain sprawl, credential
breaches, and publicly available exploits for known CVEs.

Each finding is saved to red_findings via the save_red_finding tool — the model
decides what merits saving, which keeps false-positive noise low.
"""

import logging
from typing import Callable, Optional

from backend.agents.tool_agent import ToolAgent
from backend.agents.state import ScanState  # kept for BaseAgent.run() signature compat
from backend.agents.tools.dns_intel import check_dns_security
from backend.agents.tools.http_probe import check_exposed_paths, check_security_headers
from backend.agents.tools.ssl_checker import check_ssl_tls
from backend.agents.tools.subdomain_enum import enumerate_subdomains
from backend.agents.tools.exploit_intel import lookup_exploits
from backend.agents.tools.web_search import web_search
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

# ── Tool definitions (OpenAI function-calling schema) ─────────────────────────

_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_asset_findings",
            "description": "Retrieve existing scan findings for an asset so you can prioritise what to investigate.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "Asset UUID"},
                    "min_severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "description": "Minimum severity to return (default: low)",
                    },
                },
                "required": ["asset_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_dns_security",
            "description": "Analyse email-security DNS records (SPF, DMARC, DKIM) and test for zone transfer.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain name to check"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_exposed_paths",
            "description": "Probe a web server for exposed sensitive files and admin paths (.env, .git, admin/, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "Base URL to probe (e.g. https://example.com)"},
                },
                "required": ["base_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_security_headers",
            "description": "Fetch a URL and check which security response headers are missing or misconfigured.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_ssl_tls",
            "description": "Inspect TLS certificate (expiry, SANs) and negotiated protocol/cipher for weaknesses.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 443},
                },
                "required": ["host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_subdomains",
            "description": "Discover subdomains via Certificate Transparency logs (crt.sh).",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_exploits",
            "description": "Search for public exploits and PoC code for a CVE on GitHub and in local KEV/EPSS data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2024-1234"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hibp_domain_check",
            "description": "Check if the domain appears in known credential breach datasets (HIBP).",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for threat intelligence, vendor advisories, or context about a vulnerability.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_attack_chain",
            "description": (
                "Persist a multi-step attack chain that combines weaknesses across TWO OR MORE "
                "assets into a more severe compromise scenario than any single finding shows on "
                "its own (e.g. a leaked credential on asset A plus an exposed admin path on "
                "asset B). Use this INSTEAD of save_red_finding for cross-asset scenarios — a "
                "single-asset issue still belongs in save_red_finding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short title of the chain"},
                    "narrative": {
                        "type": "string",
                        "description": "Step-by-step attacker narrative naming which asset/weakness each step uses",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "asset_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "UUIDs of every asset involved in the chain, in the order they're used",
                    },
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "asset_id": {"type": "string"},
                                "weakness": {"type": "string"},
                            },
                        },
                        "description": "Ordered breakdown of the chain: one weakness per asset hop",
                    },
                },
                "required": ["title", "narrative", "severity", "asset_ids"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_red_finding",
            "description": (
                "Persist a confirmed attack-surface finding to the database. "
                "Call this only for genuine issues, not informational observations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short title of the finding"},
                    "description": {"type": "string", "description": "Technical description of the issue"},
                    "attack_scenario": {
                        "type": "string",
                        "description": "Concrete narrative: how an attacker would exploit this step by step",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "category": {
                        "type": "string",
                        "enum": ["dns", "ssl", "headers", "exposed_path", "subdomain", "breach", "exploit", "network", "other"],
                    },
                    "evidence": {
                        "type": "object",
                        "description": "Raw data from the tool that revealed this finding",
                    },
                    "asset_id": {
                        "type": "string",
                        "description": "UUID of the asset this finding applies to",
                    },
                },
                "required": ["title", "description", "severity", "category"],
            },
        },
    },
]

_SYSTEM = """\
You are a red team security analyst. Your mission is to find security weaknesses \
in an organisation's digital assets by thinking like an external attacker.

You have tools to check DNS email-security (SPF/DMARC/DKIM), probe for exposed sensitive \
files, analyse TLS configuration, enumerate subdomains, search for public exploits, check \
for credential breaches, and search the web for threat intelligence.

For each asset:
1. Review existing scan findings to understand what is already known.
2. Check what automated scanners typically miss: DNS misconfigs, weak email security, \
   missing headers, exposed admin/backup paths, weak TLS, subdomain sprawl.
3. For CVEs in existing findings with high CVSS, check if public exploits exist.
4. Save real findings using save_red_finding. Do NOT save informational observations. \
   Each saved finding must have a concrete attack_scenario explaining how an attacker \
   would actually exploit it.

After going through every asset individually, step back and look ACROSS all of them together:
5. Attack chains: does a weakness on one asset combine with a weakness on a DIFFERENT asset \
   into a more severe scenario than either shows alone? (e.g. a credential breach for asset A's \
   domain plus an exposed admin panel on asset B — the leaked credential logs into that panel.) \
   Save any genuine cross-asset chain with save_attack_chain, naming every asset involved. \
   A single-asset issue still belongs in save_red_finding, not here.

Be thorough. A finding with a clear attack scenario is worth ten vague observations."""


class RedAgent(ToolAgent):
    agent_type = "red"

    def run(self, state: ScanState) -> ScanState:
        """Not used — RedAgent runs at org scope, not per-scan. See run_for_org()."""
        return state

    def run_for_org(
        self,
        org_id: str,
        run_id: str | None = None,
        emit: Optional[Callable[[dict], None]] = None,
        job_id: Optional[str] = None,
    ) -> dict:
        """
        Run the full red-team cycle for all assets in an org.
        Returns a summary dict with findings_created count.
        """
        assets = (
            supabase.table("assets")
            .select("id, name, host, type, is_internal")
            .eq("org_id", org_id)
            .eq("is_active", True)
            .execute()
            .data or []
        )
        if not assets:
            logger.info("RedAgent: no active assets for org %s", org_id)
            return {"findings_created": 0}

        executor = _build_executor(org_id, run_id, emit=emit)

        asset_summaries = "\n".join(
            f"- id={a['id']} name={a['name']} host={a['host']} type={a['type']} internal={a['is_internal']}"
            for a in assets
        )
        user_content = (
            f"Analyse all assets for org_id={org_id}.\n\nAssets:\n{asset_summaries}\n\n"
            "Work through each asset. Use the available tools to probe attack surface. "
            "Save findings for every genuine security issue you discover."
        )

        try:
            self.run_with_tools(_SYSTEM, user_content, _TOOLS, executor, emit=emit, job_id=job_id, org_id=org_id)
        except Exception as e:
            logger.error("RedAgent failed for org %s: %s", org_id, e)

        # Count what was saved during the run
        count = executor["_state"]["findings_created"]
        logger.info("RedAgent: %d finding(s) saved for org %s", count, org_id)
        return {"findings_created": count}


# ── Tool executor ─────────────────────────────────────────────────────────────

def _build_executor(
    org_id: str,
    run_id: str | None,
    emit: Optional[Callable[[dict], None]] = None,
) -> dict:
    """Returns the tool executor dict, capturing org_id and run_id as closure."""
    state = {"findings_created": 0}

    def get_asset_findings(asset_id: str, min_severity: str = "low") -> dict:
        sev_order = ["info", "low", "medium", "high", "critical"]
        min_idx = sev_order.index(min_severity) if min_severity in sev_order else 1
        allowed = sev_order[min_idx:]
        rows = (
            supabase.table("findings")
            .select("title, severity, cve_ids, raw_data")
            .eq("asset_id", asset_id)
            .eq("status", "open")
            .in_("severity", allowed)
            .limit(30)
            .execute()
            .data or []
        )
        return {"asset_id": asset_id, "findings": rows, "count": len(rows)}

    def hibp_domain_check(domain: str) -> dict:
        try:
            from backend.core.hibp import check_domain
            return check_domain(domain)
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    def save_attack_chain(
        title: str,
        narrative: str,
        severity: str,
        asset_ids: list[str],
        steps: list[dict] | None = None,
    ) -> dict:
        # Reuses red_findings (category="attack_chain") rather than a dedicated table: no
        # single asset_id applies to a cross-asset chain, so the asset list and step
        # breakdown go in `evidence` — already a free-form jsonb column on this table.
        row = {
            "org_id": org_id,
            "title": title,
            "description": narrative,
            "attack_scenario": narrative,
            "severity": severity,
            "category": "attack_chain",
            "evidence": {"asset_ids": asset_ids, "steps": steps or []},
            "status": "open",
        }
        if run_id:
            row["run_id"] = run_id

        try:
            res = supabase.table("red_findings").insert(row).execute()
            state["findings_created"] += 1
            if emit:
                emit({"type": "finding_saved", "agent": "red", "title": title, "severity": severity, "category": "attack_chain"})
            return {"saved": True, "id": res.data[0]["id"]}
        except Exception as e:
            logger.error("save_attack_chain failed: %s", e)
            return {"saved": False, "error": str(e)}

    def save_red_finding(
        title: str,
        description: str,
        severity: str,
        category: str,
        attack_scenario: str = "",
        evidence: dict | None = None,
        asset_id: str | None = None,
    ) -> dict:
        row = {
            "org_id": org_id,
            "title": title,
            "description": description,
            "attack_scenario": attack_scenario,
            "severity": severity,
            "category": category,
            "evidence": evidence or {},
            "status": "open",
        }
        if asset_id:
            row["asset_id"] = asset_id
        if run_id:
            row["run_id"] = run_id

        try:
            res = supabase.table("red_findings").insert(row).execute()
            state["findings_created"] += 1
            if emit:
                emit({"type": "finding_saved", "agent": "red", "title": title, "severity": severity, "category": category})
            return {"saved": True, "id": res.data[0]["id"]}
        except Exception as e:
            logger.error("save_red_finding failed: %s", e)
            return {"saved": False, "error": str(e)}

    return {
        "_state": state,
        "get_asset_findings": get_asset_findings,
        "check_dns_security": check_dns_security,
        "check_exposed_paths": check_exposed_paths,
        "check_security_headers": check_security_headers,
        "check_ssl_tls": check_ssl_tls,
        "enumerate_subdomains": enumerate_subdomains,
        "lookup_exploits": lookup_exploits,
        "hibp_domain_check": hibp_domain_check,
        "web_search": web_search,
        "save_red_finding": save_red_finding,
        "save_attack_chain": save_attack_chain,
    }
