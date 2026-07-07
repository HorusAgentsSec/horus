"""
BlueAgent — defensive response agent.

Reads open red_findings (attack-surface hypotheses from RedAgent) and generates
concrete, actionable remediation guidance for each one. It can search the web
for vendor advisories, CIS benchmarks, and patch documentation, and uses the
local CVE/KEV database for context.

The respond_to_finding tool writes back a structured blue_response to the DB
and flips status to 'responded'.
"""

import logging
from typing import Callable, Optional

from backend.agents.tool_agent import ToolAgent
from backend.agents.state import ScanState
from backend.agents.tools.web_search import web_search
from backend.agents.tools.exploit_intel import lookup_exploits
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

# ── Tool definitions ──────────────────────────────────────────────────────────

_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_pending_red_findings",
            "description": "Fetch open red team findings that haven't been responded to yet.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 20, "description": "Max findings to return"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_details",
            "description": "Retrieve KEV/EPSS/CVSS details for a CVE from the local intelligence database.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "e.g. CVE-2024-1234"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_exploits",
            "description": "Check exploit availability for a CVE (GitHub PoCs, KEV status).",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search for vendor advisories, patches, hardening guides, or CIS benchmarks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "respond_to_finding",
            "description": (
                "Write a structured remediation response for a red finding and mark it as 'responded'. "
                "Call this once per finding after you have researched the remediation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "UUID of the red_finding"},
                    "summary": {"type": "string", "description": "One-paragraph explanation of the root cause"},
                    "remediation_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Ordered list of concrete remediation steps",
                    },
                    "config_snippet": {
                        "type": "string",
                        "description": "Relevant config / command snippet (optional)",
                    },
                    "verification": {
                        "type": "string",
                        "description": "How to verify the fix was applied correctly",
                    },
                    "effort": {
                        "type": "string",
                        "enum": ["minutes", "hours", "days"],
                        "description": "Estimated implementation effort",
                    },
                    "references": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "URLs for advisories, patches, or hardening guides",
                    },
                },
                "required": ["finding_id", "summary", "remediation_steps"],
            },
        },
    },
]

_SYSTEM = """\
You are a blue team security engineer. Your job is to review attack findings from \
the red team and produce concrete, actionable remediation guidance.

Workflow:
1. Call get_pending_red_findings to load what the red team found.
2. For each finding:
   a. Understand the root cause — not just the symptom.
   b. If it mentions a CVE, call get_cve_details and lookup_exploits for urgency context.
   c. Search the web for the most current fix: vendor advisory, patch, or hardening guide.
   d. Call respond_to_finding with a response that a developer or sysadmin can act on immediately.
3. Be specific. "Update your DNS records" is not useful. \
   "Add a DMARC record: _dmarc.example.com TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com" is.

Quality bar: every response must include at minimum:
- A clear root-cause explanation.
- Step-by-step remediation with concrete values (not placeholders).
- A verification command or test to confirm the fix worked."""


class BlueAgent(ToolAgent):
    agent_type = "blue"

    def run(self, state: ScanState) -> ScanState:
        """Not used — BlueAgent runs at org scope. See run_for_org()."""
        return state

    def run_for_org(
        self,
        org_id: str,
        emit: Optional[Callable[[dict], None]] = None,
        job_id: Optional[str] = None,
    ) -> dict:
        """
        Respond to all open red findings for an org.
        Returns a summary dict with responses_created count.
        """
        # Check if there are open findings before spending tokens
        pending = (
            supabase.table("red_findings")
            .select("id")
            .eq("org_id", org_id)
            .eq("status", "open")
            .limit(1)
            .execute()
            .data or []
        )
        if not pending:
            logger.info("BlueAgent: no open red findings for org %s", org_id)
            return {"responses_created": 0}

        executor = _build_executor(org_id, emit=emit)
        user_content = (
            f"Review and respond to all open red team findings for org_id={org_id}. "
            "Start by calling get_pending_red_findings, then work through each one."
        )

        try:
            self.run_with_tools(_SYSTEM, user_content, _TOOLS, executor, emit=emit, job_id=job_id, org_id=org_id)
        except Exception as e:
            logger.error("BlueAgent failed for org %s: %s", org_id, e)

        count = executor["_state"]["responses_created"]
        logger.info("BlueAgent: %d response(s) written for org %s", count, org_id)
        return {"responses_created": count}


# ── Tool executor ─────────────────────────────────────────────────────────────

def _build_executor(
    org_id: str,
    emit: Optional[Callable[[dict], None]] = None,
) -> dict:
    state = {"responses_created": 0}

    def get_pending_red_findings(limit: int = 20) -> dict:
        rows = (
            supabase.table("red_findings")
            .select("id, title, description, attack_scenario, severity, category, evidence")
            .eq("org_id", org_id)
            .eq("status", "open")
            .order("severity", desc=True)   # critical first
            .limit(limit)
            .execute()
            .data or []
        )
        return {"findings": rows, "count": len(rows)}

    def get_cve_details(cve_id: str) -> dict:
        try:
            from backend.core.cve_intel import lookup_cves
            intel = lookup_cves([cve_id.upper()])
            row = intel.get(cve_id.upper())
            return row or {"cve_id": cve_id, "note": "Not in local CVE database"}
        except Exception as e:
            return {"cve_id": cve_id, "error": str(e)}

    def respond_to_finding(
        finding_id: str,
        summary: str,
        remediation_steps: list[str],
        config_snippet: str = "",
        verification: str = "",
        effort: str = "hours",
        references: list[str] | None = None,
    ) -> dict:
        blue_response = {
            "summary": summary,
            "remediation_steps": remediation_steps,
            "config_snippet": config_snippet,
            "verification": verification,
            "effort": effort,
            "references": references or [],
        }
        try:
            supabase.table("red_findings").update({
                "status": "responded",
                "blue_response": blue_response,
            }).eq("id", finding_id).eq("org_id", org_id).execute()
            state["responses_created"] += 1
            if emit:
                emit({"type": "response_saved", "agent": "blue", "effort": effort})
            return {"saved": True, "finding_id": finding_id}
        except Exception as e:
            logger.error("respond_to_finding failed for %s: %s", finding_id, e)
            return {"saved": False, "error": str(e)}

    return {
        "_state": state,
        "get_pending_red_findings": get_pending_red_findings,
        "get_cve_details": get_cve_details,
        "lookup_exploits": lookup_exploits,
        "web_search": web_search,
        "respond_to_finding": respond_to_finding,
    }
