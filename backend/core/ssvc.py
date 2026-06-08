"""
SSVC — Stakeholder-Specific Vulnerability Categorization (deployer tree).

The deterministic priority engine behind remediation urgency. CVSS asks "how bad is this bug in
the abstract"; SSVC asks "what should *we* do about it, given how exploited it is and how exposed
*we* are." That contextual, decision-oriented framing (CISA's deployer model) is what a blue team
actually needs, and it's fully derivable from signals we already compute — no LLM, no guesswork.

Decision points (CISA SSVC deployer):
  - Exploitation:     none | poc | active     (from KEV + EPSS, via ThreatIntelAgent)
  - Exposure:         small | controlled | open  (internet-facing vs internal)
  - Automatable:      yes | no                 (can recon→exploit be automated end-to-end)
  - Technical impact: partial | total          (bounded subsystem vs full control)

Outcome (priority label, in increasing urgency): track < track_star < attend < act.
Each maps to a default remediation mode (suggest_only / approval_required), which the org's
explicit permission rules can still override upstream.

`decide()` is a pure function over the four decision points and is unit-tested. The `*_from_*`
mappers translate our finding signals into those points and are deliberately conservative
(default to the less-urgent branch when a signal is missing), so we never over-escalate on a guess.
"""

from dataclasses import dataclass

# ── Decision-point vocabularies (ordinal where it matters) ──────────────────────
EXPLOITATION = ("none", "poc", "active")
EXPOSURE = ("small", "controlled", "open")
TECHNICAL_IMPACT = ("partial", "total")

# Priority labels, least → most urgent. "track_star" is SSVC's "Track*" (track, but revisit if
# anything changes). Kept as an identifier-safe slug; humanize() renders it for the UI.
PRIORITY_ORDER = ("track", "track_star", "attend", "act")

# Default remediation mode per priority. Permission rules (resolve_mode) take precedence; this is
# only the fallback when no explicit rule matches.
_MODE_BY_PRIORITY = {
    "act": "approval_required",
    "attend": "approval_required",
    "track_star": "suggest_only",
    "track": "suggest_only",
}

_PRIORITY_LABEL = {
    "act": "Act",
    "attend": "Attend",
    "track_star": "Track*",
    "track": "Track",
}


@dataclass(frozen=True)
class SSVCResult:
    priority: str          # one of PRIORITY_ORDER
    mode: str              # default remediation mode for this priority
    exploitation: str
    exposure: str
    automatable: bool
    technical_impact: str
    rationale: str

    def as_dict(self) -> dict:
        return {
            "priority": self.priority,
            "label": _PRIORITY_LABEL[self.priority],
            "mode": self.mode,
            "exploitation": self.exploitation,
            "exposure": self.exposure,
            "automatable": self.automatable,
            "technical_impact": self.technical_impact,
            "rationale": self.rationale,
        }


def humanize(priority: str) -> str:
    return _PRIORITY_LABEL.get(priority, priority)


def decide(
    exploitation: str,
    exposure: str,
    automatable: bool,
    technical_impact: str,
) -> SSVCResult:
    """Pure SSVC deployer decision tree → priority. Exploitation dominates (active in-the-wild
    outranks everything), then exposure + automatability (how easily value is reached), then
    technical impact. Conservative ties resolve downward."""
    exp = exploitation if exploitation in EXPLOITATION else "none"
    expo = exposure if exposure in EXPOSURE else "controlled"
    impact = technical_impact if technical_impact in TECHNICAL_IMPACT else "partial"
    total = impact == "total"

    if exp == "active":
        # Actively exploited: at minimum Attend; Act when exposed and (wormable or full-impact).
        if expo == "open" and (automatable or total):
            priority, why = "act", "Active exploitation on an internet-facing asset"
        elif expo == "open":
            priority, why = "attend", "Active exploitation, internet-facing but limited impact"
        elif expo == "controlled" and automatable and total:
            priority, why = "act", "Active exploitation, automatable with total impact"
        else:
            priority, why = "attend", "Active exploitation on a non-public asset"
    elif exp == "poc":
        # Public PoC / elevated EPSS: weaponization is plausible.
        if expo == "open" and automatable and total:
            priority, why = "act", "Public exploit, internet-facing, automatable and total impact"
        elif expo == "open" and (automatable or total):
            priority, why = "attend", "Public exploit on an internet-facing asset"
        elif expo == "small":
            priority, why = "track", "Public exploit but minimal exposure"
        else:
            priority, why = "track_star", "Public exploit; watch for exposure or impact changes"
    else:  # none
        if expo == "open" and automatable and total:
            priority, why = "attend", "No known exploitation, but exposed, automatable and total impact"
        elif expo == "open" and total:
            priority, why = "track_star", "No known exploitation; exposed with total impact"
        else:
            priority, why = "track", "No known exploitation signal"

    return SSVCResult(
        priority=priority,
        mode=_MODE_BY_PRIORITY[priority],
        exploitation=exp,
        exposure=expo,
        automatable=automatable,
        technical_impact=impact,
        rationale=why,
    )


# ── Mappers: our finding signals → SSVC decision points ─────────────────────────

def exploitation_from(exploitability: str | None, public_exploits_exist: bool = False) -> str:
    """ThreatIntelAgent's exploitability (derived from KEV + EPSS) → SSVC Exploitation.
    active(KEV) → active; high/medium EPSS or a known public exploit → poc; otherwise none."""
    e = (exploitability or "none").lower()
    if e == "active":
        return "active"
    if e in ("high", "medium") or public_exploits_exist:
        return "poc"
    return "none"


def exposure_from(is_internal: bool) -> str:
    """Internet-facing assets are 'open'; internal assets are 'controlled'. We don't currently
    distinguish 'small' (no signal for it), so we never under-rate an internal asset to 'small'."""
    return "controlled" if is_internal else "open"


def technical_impact_from(severity: str | None, cvss_score: float | None) -> str:
    """Total = full control / critical class; partial otherwise. CVSS ≥ 9.0 or a 'critical'
    severity ⇒ total."""
    if cvss_score is not None and cvss_score >= 9.0:
        return "total"
    if (severity or "").lower() == "critical":
        return "total"
    return "partial"


def automatable_from(exploitation: str, severity: str | None, public_exploits_exist: bool) -> bool:
    """Conservative heuristic for SSVC Automatable: an attacker can reliably automate the full
    recon→exploit chain. We treat it as yes only when there's a real weaponization signal (active
    exploitation or a public exploit) on a high/critical-severity issue; otherwise no. SSVC defaults
    Automatable to 'no' under uncertainty, and so do we."""
    sev = (severity or "").lower()
    high_sev = sev in ("critical", "high")
    return high_sev and (exploitation == "active" or public_exploits_exist)


def assess(
    *,
    exploitability: str | None,
    public_exploits_exist: bool,
    severity: str | None,
    cvss_score: float | None,
    is_internal: bool,
) -> SSVCResult:
    """Convenience: map a finding's signals straight to an SSVCResult."""
    exploitation = exploitation_from(exploitability, public_exploits_exist)
    return decide(
        exploitation=exploitation,
        exposure=exposure_from(is_internal),
        automatable=automatable_from(exploitation, severity, public_exploits_exist),
        technical_impact=technical_impact_from(severity, cvss_score),
    )
