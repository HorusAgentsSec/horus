"""
Tests for remediation safety — the hard ceiling on auto-execution autonomy.

Covers the pure classifier (action type + dangerous-command detection), the autonomy clamp, and the
key trust guarantee end-to-end: a permission rule that says "auto" cannot make a destructive fix
auto-execute — the RiskManager caps it.
"""

from backend.agents.risk_manager_agent import RiskManagerAgent
from backend.agents.state import (
    AnalyzedFinding, AssetInfo, EnrichedFinding, RemediationSuggestion, ScanState,
)
from backend.core import remediation_safety as rs


# ── classify_safety ──────────────────────────────────────────────────────────────

def test_action_type_default_tiers():
    assert rs.classify_safety("block_ip", None) == rs.REVERSIBLE
    assert rs.classify_safety("apply_firewall_rule", "iptables -A INPUT -s 1.2.3.4 -j DROP") == rs.REVERSIBLE
    assert rs.classify_safety("update_library", "apt upgrade nginx") == rs.DISRUPTIVE
    assert rs.classify_safety("rotate_credentials", None) == rs.DISRUPTIVE
    assert rs.classify_safety("unknown_action", None) == rs.DISRUPTIVE  # default disruptive


def test_dangerous_commands_force_destructive():
    # The command text overrides a benign-looking action_type.
    assert rs.classify_safety("update_library", "rm -rf /var/www") == rs.DESTRUCTIVE
    assert rs.classify_safety("patch_config", "DROP TABLE users;") == rs.DESTRUCTIVE
    assert rs.classify_safety("other", "mkfs.ext4 /dev/sda1") == rs.DESTRUCTIVE
    assert rs.classify_safety("restart_service", "shutdown -h now") == rs.DESTRUCTIVE
    assert rs.classify_safety("disable_feature", "git push origin main --force") == rs.DESTRUCTIVE


# ── clamp_to_safety ──────────────────────────────────────────────────────────────

def test_clamp_lowers_but_never_raises():
    # auto requested, but tier caps it
    assert rs.clamp_to_safety("auto", rs.DESTRUCTIVE) == "suggest_only"
    assert rs.clamp_to_safety("auto", rs.DISRUPTIVE) == "approval_required"
    assert rs.clamp_to_safety("auto", rs.REVERSIBLE) == "auto"
    # a stricter requested mode is never raised toward the ceiling
    assert rs.clamp_to_safety("suggest_only", rs.REVERSIBLE) == "suggest_only"
    assert rs.clamp_to_safety("approval_required", rs.REVERSIBLE) == "approval_required"


# ── RiskManager end-to-end: safety overrides an "auto" permission rule ────────────

def _state(action_type, command, rules):
    sug = RemediationSuggestion(
        finding_id="f1", action_type=action_type, title="fix", description="d",
        command_or_patch=command, estimated_risk="low", confidence=0.9,
    )
    return ScanState(
        scan_id="s", org_id="o",
        asset=AssetInfo(id="a", name="web", host="h", type="domain", is_internal=True, tags=[]),
        analyzed_findings=[AnalyzedFinding(id="f1", title="t", description="d", severity="high",
                                           confidence=0.8, rationale="r")],
        enriched_findings=[EnrichedFinding(finding_id="f1", threat_context="", exploitability="none",
                                           public_exploits_exist=False)],
        remediation_suggestions=[sug],
        permission_rules=rules,
    )


def test_auto_rule_cannot_auto_run_destructive():
    rules = [{"name": "trust-all", "action": "*", "mode": "auto"}]
    state = _state("update_library", "rm -rf /data", rules)
    RiskManagerAgent().run(state)
    d = state.risk_decisions[0]
    assert d.safety_tier == rs.DESTRUCTIVE
    assert d.mode == "suggest_only"          # capped despite the auto rule
    assert "capped" in d.reason


def test_auto_rule_allowed_for_reversible():
    rules = [{"name": "trust-all", "action": "*", "mode": "auto"}]
    state = _state("block_ip", "iptables -A INPUT -s 1.2.3.4 -j DROP", rules)
    RiskManagerAgent().run(state)
    d = state.risk_decisions[0]
    assert d.safety_tier == rs.REVERSIBLE
    assert d.mode == "auto"                  # reversible may auto-run


def test_ssvc_path_also_clamped():
    # No matching rule → SSVC decides, then safety still caps a destructive fix.
    state = _state("patch_config", "drop database prod;", rules=[])
    RiskManagerAgent().run(state)
    d = state.risk_decisions[0]
    assert d.safety_tier == rs.DESTRUCTIVE
    assert d.mode == "suggest_only"
