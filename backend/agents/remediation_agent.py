"""
RemediationAgent — generates concrete remediation suggestions per finding.
Receives analyzed + enriched findings + asset context.
"""

import json
import logging
from backend.agents.base import BaseAgent
from backend.agents.state import ScanState, RemediationSuggestion
from backend.core.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security remediation engineer. You will receive vulnerability findings with threat intelligence context.

For each finding, generate a remediation suggestion as a JSON object:
{
  "finding_id": "<same id as input finding>",
  "action_type": "<update_library|apply_firewall_rule|restart_service|block_ip|patch_config|disable_feature|rotate_credentials|other>",
  "title": "<concise action title>",
  "description": "<step-by-step remediation instructions>",
  "command_or_patch": "<shell command, config snippet, or null if not applicable>",
  "estimated_risk": "<low|medium|high>",
  "confidence": <0.0-1.0>
}

Consider:
- Asset context (internal vs external, tags) when crafting safe commands
- The estimated_risk is the risk of APPLYING the fix (not the vulnerability itself)
- Only include command_or_patch when you are confident it is safe and correct
- Keep "description" to short, numbered steps; no prose padding

Respond ONLY with a valid JSON array."""


class RemediationAgent(BaseAgent):
    agent_type = "remediation"

    def run(self, state: ScanState) -> ScanState:
        if not state.analyzed_findings:
            return state

        # No-cloud mode: remediation drafting is inherently an LLM task — skip it. Findings still
        # carry their SSVC priority, so the user gets prioritized exposure without any LLM call.
        if not settings.llm_enabled:
            logger.info("RemediationAgent: skipped (no-cloud mode)")
            return state

        # Build enrichment map for quick lookup
        enrichment_map = {e.finding_id: e for e in state.enriched_findings}

        # Skip findings the validation debate judged false positive — no point drafting (and paying
        # for) a fix for something we don't believe is real.
        candidates = [f for f in state.analyzed_findings if f.verdict != "false_positive"]
        skipped = len(state.analyzed_findings) - len(candidates)
        if skipped:
            logger.info("RemediationAgent: skipping %d false-positive finding(s)", skipped)

        payload = []
        for f in candidates:
            enrichment = enrichment_map.get(f.id)
            entry = {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "cve_ids": f.cve_ids,
                "exploitability": enrichment.exploitability if enrichment else "unknown",
                "threat_context": enrichment.threat_context if enrichment else "",
            }
            payload.append(entry)

        asset_context = (
            f"Asset: {state.asset.name} ({state.asset.host}), "
            f"type={state.asset.type}, "
            f"internal={state.asset.is_internal}, "
            f"tags={state.asset.tags}"
        )

        user_content = f"{asset_context}\n\nFindings:\n{json.dumps(payload, separators=(',', ':'))}"

        raw, tokens = self.call_llm_json(SYSTEM_PROMPT, user_content, max_tokens=4096)

        if not isinstance(raw, list):
            raw = [raw]

        suggestions = []
        for item in raw:
            try:
                suggestions.append(RemediationSuggestion(**item))
            except Exception as e:
                logger.warning(f"RemediationAgent: skipping item: {e}")

        state.remediation_suggestions = suggestions
        logger.info(f"RemediationAgent: generated {len(suggestions)} suggestions, {tokens} tokens")
        return state
