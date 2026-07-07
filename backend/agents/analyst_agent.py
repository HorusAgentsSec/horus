"""
AnalystAgent — classifies raw findings, assigns severity, generates fingerprints.

Routes each raw finding to a domain specialist (web / network / TLS) and runs the specialists in
parallel (the TradingAgents "analyst team" pattern), then merges and fingerprints the results. Falls
back to a single generalist call when there's only one domain in play or the team is disabled. The
output (AnalyzedFinding list) is unchanged, so the rest of the pipeline doesn't care how it was made.
"""

import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor

from backend.agents import analyst_team
from backend.agents.base import BaseAgent
from backend.agents.state import ScanState, AnalyzedFinding
from backend.core.config import settings

logger = logging.getLogger(__name__)

# Generalist prompt — used when the analyst team is disabled or only one domain is present.
SYSTEM_PROMPT = analyst_team.system_prompt_for(analyst_team.GENERIC)

_MAX_PARALLEL = 4


class AnalystAgent(BaseAgent):
    agent_type = "analyst"

    def run(self, state: ScanState) -> ScanState:
        if not state.raw_findings:
            return state

        # Group findings by specialist domain (also used for the log line).
        groups: dict[str, list] = {}
        for f in state.raw_findings:
            groups.setdefault(analyst_team.classify_domain(f), []).append(f)

        if not settings.llm_enabled:
            # No-cloud mode: classify deterministically from the scanner output, no LLM.
            results = self._run_deterministic(state)
        elif settings.analyst_team_enabled and len(groups) > 1:
            # Fan out to domain specialists in parallel.
            results = self._run_team(state, groups)
        else:
            results = self._run_single(state)

        analyzed = []
        for item in results:
            item["id"] = _fingerprint(state.asset.id, item)
            try:
                analyzed.append(AnalyzedFinding(**item))
            except Exception as e:
                logger.warning(f"AnalystAgent: skipping malformed finding: {e}")

        state.analyzed_findings = analyzed
        mode = "no-cloud" if not settings.llm_enabled else f"{len(groups)} domain(s)"
        logger.info(
            "AnalystAgent: produced %d analyzed findings (%s), %d tokens",
            len(analyzed), mode, self.tokens_used,
        )
        return state

    def _run_team(self, state: ScanState, groups: dict[str, list]) -> list[dict]:
        """Run one SpecialistAnalyst per domain concurrently; merge their outputs."""
        merged: list[dict] = []

        def work(domain: str, findings: list):
            specialist = analyst_team.SpecialistAnalyst()
            specialist.redactor = self.redactor  # propagate privacy to the parallel specialists
            raw, _ = specialist.analyze(state.asset.id, state.asset.host, domain, findings)
            return raw, specialist.tokens_used, specialist.model_used

        with ThreadPoolExecutor(max_workers=min(len(groups), _MAX_PARALLEL)) as pool:
            futures = {pool.submit(work, d, fs): d for d, fs in groups.items()}
            for fut in futures:
                domain = futures[fut]
                try:
                    raw, tokens, model = fut.result()
                    merged.extend(raw)
                    self.tokens_used += tokens  # main thread aggregates → no race
                    self.model_used = model or self.model_used
                except Exception as e:
                    logger.warning("AnalystAgent: %s specialist failed: %s", domain, e)
        return merged

    def _run_deterministic(self, state: ScanState) -> list[dict]:
        """No-cloud classification: trust the scanner's own severity and output, no LLM. CVE
        enrichment still happens downstream (Correlation + ThreatIntel are deterministic). Confidence
        is a neutral 0.5 — unverified — so the validation gate flags these as needs_verification."""
        out = []
        for rf in state.raw_findings:
            raw = rf.raw if isinstance(rf.raw, dict) else {}
            desc = (raw.get("output") or rf.name or "").strip()[:300]
            out.append({
                "raw": {"tool": rf.tool, "template_id": rf.template_id},
                "title": rf.name,
                "description": desc or rf.name,
                "severity": rf.severity,
                "cvss_score": None,
                "cve_ids": [],
                "confidence": 0.5,
                "rationale": "Classified from scanner output without an LLM (no-cloud mode).",
            })
        return out

    def _run_single(self, state: ScanState) -> list[dict]:
        import json

        findings_json = json.dumps(
            [f.model_dump() for f in state.raw_findings], separators=(",", ":")
        )
        user_content = (
            f"Asset ID: {state.asset.id}\nAsset host: {state.asset.host}\n\n"
            f"Raw findings:\n{findings_json}"
        )
        raw, _ = self.call_llm_json(SYSTEM_PROMPT, user_content, max_tokens=4096)
        return raw if isinstance(raw, list) else [raw]


def _fingerprint(asset_id: str, item: dict) -> str:
    raw_finding = item.get("raw", {})
    tool = raw_finding.get("tool", "unknown")
    template_id = raw_finding.get("template_id") or item.get("title", "")
    key = f"{asset_id}:{tool}:{template_id}"
    return hashlib.sha256(key.encode()).hexdigest()
