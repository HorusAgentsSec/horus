"""
ReporterAgent — generates the final scan report summary.

Writes for a blue team using the whole pipeline's intelligence: it ignores findings the validation
debate judged false positives, and orders the top priorities by SSVC (the contextual urgency) rather
than raw severity — so the executive summary leads with what actually needs doing. The report is
persisted on the scan and shown in the UI.
"""

import json
import logging

from backend.agents.base import BaseAgent
from backend.agents.state import ScanState, ScanReport
from backend.core import ssvc
from backend.core.config import settings

logger = logging.getLogger(__name__)

_SEVERITY_RANK = ["critical", "high", "medium", "low", "info"]
_SSVC_RANK = {p: i for i, p in enumerate(reversed(ssvc.PRIORITY_ORDER))}  # act=0 (most urgent)


def _as_text(value) -> str:
    """Coerce an LLM field to a string. Models differ — some return a bullet list (JSON array)
    where we expect prose (e.g. recommended_next_steps); join those rather than fail validation."""
    if isinstance(value, list):
        return "\n".join(f"- {str(v).strip()}" for v in value if str(v).strip())
    return str(value or "").strip()

SYSTEM_PROMPT = """You are a security reporting specialist writing for a blue team.
You will receive summary statistics and top findings (already prioritized by SSVC urgency, with
likely false positives removed) from a security scan.

Generate a concise scan report as JSON:
{
  "summary": "<2-3 sentence executive summary of the scan results>",
  "critical_count": <int>,
  "high_count": <int>,
  "medium_count": <int>,
  "low_count": <int>,
  "top_priorities": ["<finding_id_1>", "<finding_id_2>", ...],
  "recommended_next_steps": "<concrete prioritized action items, 3-5 bullet points>"
}

Lead with the SSVC 'Act'/'Attend' items. Be direct and actionable; focus on risk, not on describing
what the tools found. Respond ONLY with valid JSON."""


class ReporterAgent(BaseAgent):
    agent_type = "reporter"

    def run(self, state: ScanState) -> ScanState:
        # Exclude likely false positives — the report should match the posture score and alerts.
        findings = [
            f for f in state.analyzed_findings if f.verdict != "false_positive"
        ]
        enrichment = {e.finding_id: e for e in state.enriched_findings}

        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        def priority_of(f) -> str:
            e = enrichment.get(f.id)
            return ssvc.assess(
                exploitability=e.exploitability if e else None,
                public_exploits_exist=bool(e.public_exploits_exist) if e else False,
                severity=f.severity,
                cvss_score=f.cvss_score,
                is_internal=state.asset.is_internal,
            ).priority

        # Order by SSVC urgency first, then severity — the executive view of "what to do next".
        top_findings = sorted(
            findings,
            key=lambda f: (_SSVC_RANK.get(priority_of(f), 99), _SEVERITY_RANK.index(f.severity)),
        )[:10]

        slim = [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "priority": ssvc.humanize(priority_of(f)), "rationale": f.rationale,
            }
            for f in top_findings
        ]

        # No-cloud mode: build the report deterministically from counts + SSVC ordering, no LLM.
        if not settings.llm_enabled:
            state.report = self._deterministic_report(state, findings, counts, top_findings, priority_of)
            logger.info("ReporterAgent: deterministic report (no-cloud mode)")
            return state

        user_content = (
            f"Asset: {state.asset.name} ({state.asset.host})\n"
            f"Total findings (excl. false positives): {len(findings)}\n"
            f"Severity breakdown: {json.dumps(counts)}\n\n"
            f"Top findings (SSVC-ordered):\n{json.dumps(slim, indent=2)}"
        )

        try:
            raw, tokens = self.call_llm_json(SYSTEM_PROMPT, user_content, max_tokens=1024)
            top_priorities = raw.get("top_priorities")
            if not isinstance(top_priorities, list):
                top_priorities = [f.id for f in top_findings[:5]]
            state.report = ScanReport(
                summary=_as_text(raw.get("summary")),
                critical_count=counts["critical"],
                high_count=counts["high"],
                medium_count=counts["medium"],
                low_count=counts["low"],
                top_priorities=[str(p) for p in top_priorities],
                recommended_next_steps=_as_text(raw.get("recommended_next_steps")),
            )
            logger.info(f"ReporterAgent: report generated, {tokens} tokens")
        except Exception as e:
            logger.error(f"ReporterAgent failed: {e}")
            state.errors.append(f"reporter: {e}")
            state.report = ScanReport(
                summary="Report generation failed.",
                critical_count=counts["critical"],
                high_count=counts["high"],
                medium_count=counts["medium"],
                low_count=counts["low"],
                top_priorities=[],
                recommended_next_steps="",
            )

        return state

    def _deterministic_report(self, state, findings, counts, top_findings, priority_of) -> ScanReport:
        """Templated executive report — no LLM. Leads with the SSVC Act/Attend items, same as the
        LLM version would, so the no-cloud report is still decision-oriented."""
        breakdown = ", ".join(f"{counts[s]} {s}" for s in _SEVERITY_RANK if counts.get(s)) or "no findings"
        urgent = [f for f in top_findings if priority_of(f) in ("act", "attend")]

        if not findings:
            summary = f"Scan of {state.asset.name} ({state.asset.host}) found no open findings."
        else:
            lead = (f"{len(urgent)} need attention now (SSVC Act/Attend)."
                    if urgent else "None are urgent by SSVC (no active exploitation on exposed, "
                    "high-impact assets).")
            summary = (
                f"Scan of {state.asset.name} ({state.asset.host}) found {len(findings)} open "
                f"finding(s): {breakdown}. {lead}"
            )

        steps = [
            f"[{ssvc.humanize(priority_of(f))}] {f.title}"
            for f in (urgent or top_findings[:5])
        ]
        if not steps:
            steps = ["No action required — keep monitoring (Watchtower re-checks daily)."]

        return ScanReport(
            summary=summary,
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            top_priorities=[f.id for f in top_findings[:5]],
            recommended_next_steps="\n".join(f"- {s}" for s in steps),
        )
