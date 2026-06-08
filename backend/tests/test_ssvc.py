"""
Tests for the SSVC deployer decision engine — the deterministic remediation-priority tree.

Covers the pure `decide()` tree (ordering, escalation, conservative ties) and the signal mappers
that translate our finding data (KEV/EPSS exploitability, CVSS, internal/external) into SSVC
decision points. No backend needed.
"""

from backend.core import ssvc


# ── decide(): the pure tree ─────────────────────────────────────────────────────

def test_active_exploitation_internet_facing_total_is_act():
    r = ssvc.decide("active", "open", automatable=True, technical_impact="total")
    assert r.priority == "act"
    assert r.mode == "approval_required"


def test_active_but_internal_is_attend_not_act():
    r = ssvc.decide("active", "controlled", automatable=False, technical_impact="partial")
    assert r.priority == "attend"


def test_no_exploitation_low_exposure_is_track():
    r = ssvc.decide("none", "controlled", automatable=False, technical_impact="partial")
    assert r.priority == "track"
    assert r.mode == "suggest_only"


def test_poc_exposed_automatable_total_is_act():
    r = ssvc.decide("poc", "open", automatable=True, technical_impact="total")
    assert r.priority == "act"


def test_poc_minimal_exposure_is_track():
    r = ssvc.decide("poc", "small", automatable=True, technical_impact="total")
    assert r.priority == "track"


def test_priority_is_monotonic_in_exploitation():
    """Holding exposure/impact fixed, more exploitation never lowers urgency."""
    order = {p: i for i, p in enumerate(ssvc.PRIORITY_ORDER)}
    none = ssvc.decide("none", "open", True, "total")
    poc = ssvc.decide("poc", "open", True, "total")
    active = ssvc.decide("active", "open", True, "total")
    assert order[none.priority] <= order[poc.priority] <= order[active.priority]


def test_unknown_inputs_default_conservatively():
    r = ssvc.decide("bogus", "bogus", automatable=False, technical_impact="bogus")
    assert r.exploitation == "none"
    assert r.exposure == "controlled"
    assert r.technical_impact == "partial"
    assert r.priority == "track"


# ── mappers: finding signals → decision points ──────────────────────────────────

def test_exploitation_mapping():
    assert ssvc.exploitation_from("active") == "active"
    assert ssvc.exploitation_from("high") == "poc"
    assert ssvc.exploitation_from("medium") == "poc"
    assert ssvc.exploitation_from("none", public_exploits_exist=True) == "poc"
    assert ssvc.exploitation_from("low") == "none"
    assert ssvc.exploitation_from(None) == "none"


def test_exposure_mapping():
    assert ssvc.exposure_from(is_internal=False) == "open"
    assert ssvc.exposure_from(is_internal=True) == "controlled"


def test_technical_impact_mapping():
    assert ssvc.technical_impact_from("critical", None) == "total"
    assert ssvc.technical_impact_from("high", 9.8) == "total"
    assert ssvc.technical_impact_from("high", 7.5) == "partial"
    assert ssvc.technical_impact_from("medium", None) == "partial"


def test_automatable_is_conservative():
    # Only weaponized + high severity counts as automatable.
    assert ssvc.automatable_from("active", "critical", False) is True
    assert ssvc.automatable_from("none", "critical", True) is True  # public exploit
    assert ssvc.automatable_from("active", "medium", False) is False  # not high sev
    assert ssvc.automatable_from("none", "high", False) is False  # no weaponization signal


def test_assess_end_to_end_kev_external_critical_is_act():
    r = ssvc.assess(
        exploitability="active",
        public_exploits_exist=True,
        severity="critical",
        cvss_score=9.8,
        is_internal=False,
    )
    assert r.priority == "act"
    assert r.as_dict()["label"] == "Act"


def test_assess_internal_medium_no_exploit_is_track():
    r = ssvc.assess(
        exploitability="none",
        public_exploits_exist=False,
        severity="medium",
        cvss_score=5.0,
        is_internal=True,
    )
    assert r.priority == "track"
