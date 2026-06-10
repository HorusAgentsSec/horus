"""
run_risk_manager — assigns execution mode (auto/approval_required/suggest_only)
to each remediation suggestion.

Logic: deterministic throughout. The org's explicit permission rules decide first (first match
wins); anything they don't cover falls back to the SSVC deployer assessment — the contextual
priority of the underlying finding (exploitation × exposure × automatable × impact).
No LLM: the urgency call is defensible and reproducible, like the posture score.
"""

import logging
from backend.agents.state import ScanState, RiskDecision, AssetInfo, RemediationSuggestion
from backend.core import ssvc, remediation_safety

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def resolve_mode(
    suggestion: RemediationSuggestion,
    asset: AssetInfo,
    rules: list[dict],
) -> tuple[str, str]:
    """Returns (mode, reason). Checks rules in order; first match wins. Default: suggest_only."""
    for rule in rules:
        action_match = rule.get("action") == suggestion.action_type or rule.get("action") == "*"
        if not action_match:
            continue

        conditions = rule.get("conditions", {})

        if "asset_tags" in conditions:
            required_tags = conditions["asset_tags"]
            if not any(tag in asset.tags for tag in required_tags):
                continue

        if "is_internal_only" in conditions:
            if conditions["is_internal_only"] and not asset.is_internal:
                continue

        mode = rule.get("mode", "suggest_only")
        reason = f"Matched rule '{rule.get('name', 'unnamed')}'"
        return mode, reason

    return "", ""  # no match — caller decides


def _assess_ssvc(finding_id, analyzed, enriched, asset) -> ssvc.SSVCResult:
    f = analyzed.get(finding_id)
    e = enriched.get(finding_id)
    return ssvc.assess(
        exploitability=e.exploitability if e else None,
        public_exploits_exist=bool(e.public_exploits_exist) if e else False,
        severity=f.severity if f else None,
        cvss_score=f.cvss_score if f else None,
        is_internal=asset.is_internal,
    )


def run_risk_manager(state: ScanState) -> ScanState:
    if not state.remediation_suggestions:
        return state

    analyzed = {f.id: f for f in state.analyzed_findings}
    enriched = {e.finding_id: e for e in state.enriched_findings}

    decisions = []
    ssvc_count = 0
    clamped_count = 0
    for suggestion in state.remediation_suggestions:
        mode, reason = resolve_mode(suggestion, state.asset, state.permission_rules)
        ssvc_result = None
        if not mode:
            ssvc_result = _assess_ssvc(suggestion.finding_id, analyzed, enriched, state.asset)
            mode = ssvc_result.mode
            reason = f"SSVC {ssvc.humanize(ssvc_result.priority)}: {ssvc_result.rationale}"
            ssvc_count += 1

        # Hard safety ceiling: a destructive/disruptive fix can't be auto-executed even if a
        # rule or SSVC asked for it. Safety has the final say.
        tier = remediation_safety.classify_safety(
            suggestion.action_type, suggestion.command_or_patch
        )
        clamped = remediation_safety.clamp_to_safety(mode, tier)
        if clamped != mode:
            clamped_count += 1
            reason += f" — capped to {clamped} (remediation is {tier})"
            mode = clamped

        decisions.append(
            RiskDecision(
                suggestion_id=suggestion.finding_id,
                mode=mode,
                reason=reason,
                ssvc=ssvc_result.as_dict() if ssvc_result else None,
                safety_tier=tier,
            )
        )

    state.risk_decisions = decisions
    logger.info(
        "run_risk_manager: %d decisions (%d via SSVC, %d capped by safety, 0 tokens)",
        len(decisions), ssvc_count, clamped_count,
    )
    return state
