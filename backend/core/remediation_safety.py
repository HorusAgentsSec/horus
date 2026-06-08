"""
Remediation safety — the hard ceiling on how much autonomy a fix may be granted.

SSVC decides *what* to fix (urgency); this decides *how much autonomy* the fix may get (blast
radius). They're orthogonal and both required before anything auto-applies: an Act-priority finding
with a destructive fix still must not auto-execute. This is the trust primitive — a platform earns
the right to act autonomously by provably refusing to auto-run anything dangerous.

A remediation is classified by its action type and, more importantly, the actual command/patch text
(an `update_library` that hides an `rm -rf` is destructive, not disruptive). The classification sets
a ceiling: a permission policy may be stricter than the ceiling, never looser. Deterministic and
unit-tested — no LLM in the safety decision.
"""

import re

# Safety tiers, increasing blast radius.
REVERSIBLE = "reversible"    # trivially undone: add a firewall deny, block an IP, disable a feature
DISRUPTIVE = "disruptive"    # may cause downtime / needs care: update a lib, restart, patch, rotate creds
DESTRUCTIVE = "destructive"  # data-loss / irreversible risk: rm, drop, format, force, reboot

# Execution autonomy, increasing.
_AUTONOMY_RANK = {"suggest_only": 0, "approval_required": 1, "auto": 2}

# The MOST autonomy each safety tier may be granted.
_CEILING = {
    REVERSIBLE: "auto",
    DISRUPTIVE: "approval_required",
    DESTRUCTIVE: "suggest_only",
}

# Default tier per action_type (the RemediationAgent's vocabulary).
_ACTION_TIER = {
    "block_ip": REVERSIBLE,
    "apply_firewall_rule": REVERSIBLE,
    "disable_feature": REVERSIBLE,
    "update_library": DISRUPTIVE,
    "patch_config": DISRUPTIVE,
    "restart_service": DISRUPTIVE,
    "rotate_credentials": DISRUPTIVE,
    "other": DISRUPTIVE,
}

# Command/patch patterns that force DESTRUCTIVE regardless of the declared action type. Conservative:
# when in doubt, classify *up* (less autonomy) — a false "destructive" only costs a human approval.
_DESTRUCTIVE_PATTERNS = (
    r"\brm\s+-[rf]",          # rm -rf / rm -f
    r"\brm\s+.*\*",           # rm with a glob
    r"\bdrop\s+(table|database|schema)\b",
    r"\bdelete\s+from\b",
    r"\btruncate\b",
    r"\bmkfs",
    r"\bdd\b",
    r">\s*/dev/sd",           # writing to a raw disk
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bformat\b",
    r"--force\b",
    r"\bgit\s+push\s+.*--force",
    r"\b:\s*>\s*/",           # truncate a file via redirection
)


def classify_safety(action_type: str | None, command_or_patch: str | None) -> str:
    """Safety tier for a remediation. The command text dominates — a dangerous command outranks a
    benign-looking action_type."""
    cmd = (command_or_patch or "").lower()
    if any(re.search(p, cmd) for p in _DESTRUCTIVE_PATTERNS):
        return DESTRUCTIVE
    return _ACTION_TIER.get(action_type or "other", DISRUPTIVE)


def autonomy_ceiling(tier: str) -> str:
    """The highest execution mode this safety tier permits."""
    return _CEILING.get(tier, "suggest_only")


def clamp_to_safety(mode: str, tier: str) -> str:
    """Lower `mode` to the safety tier's ceiling if it exceeds it (never raises it). This is the hard
    rule: policy/SSVC can ask for autonomy, safety has the final say."""
    ceiling = autonomy_ceiling(tier)
    if _AUTONOMY_RANK.get(mode, 0) > _AUTONOMY_RANK[ceiling]:
        return ceiling
    return mode
