"""
Tests for the Watchtower core (continuous exposure monitoring).

Covers the pure logic — intersecting the asset inventory with newly known-exploited CVEs
and the dedup behaviour — without touching Supabase or NVD. DB/feed access in watchtower.py
is lazy-imported, so importing these helpers needs no configured backend.
"""

from backend.core.watchtower import (
    _presentation,
    _severity,
    _severity_spike,
    is_epss_spike,
    match_exposures,
)


def _correlator(mapping):
    """Build a (product, version) -> [cve_id] lookup from a dict, recording calls."""
    calls = []

    def fn(product, version):
        calls.append((product, version))
        return mapping.get((product, version), [])

    fn.calls = calls
    return fn


# ── _severity ────────────────────────────────────────────────────────────────

def test_severity_maps_cvss_levels():
    assert _severity({"cvss_severity": "critical"}) == "critical"
    assert _severity({"cvss_severity": "MEDIUM"}) == "medium"
    assert _severity({"cvss_severity": "none"}) == "info"


def test_severity_floors_at_high_when_kev_without_cvss():
    # In KEV but no CVSS recorded → it is actively exploited, must not degrade to info/low.
    assert _severity({"cvss_severity": None}) == "high"
    assert _severity({}) == "high"


# ── EPSS spike detection ─────────────────────────────────────────────────────────

def test_epss_spike_requires_floor_and_delta():
    # Above floor (0.5) and rose by >= delta (0.2) → spike.
    assert is_epss_spike({"epss_score": 0.7, "epss_previous": 0.4}, 0.5, 0.2) is True


def test_epss_spike_below_floor_is_not_spike():
    # Big jump but still below the floor → not actionable.
    assert is_epss_spike({"epss_score": 0.3, "epss_previous": 0.01}, 0.5, 0.2) is False


def test_epss_spike_small_rise_is_not_spike():
    assert is_epss_spike({"epss_score": 0.9, "epss_previous": 0.85}, 0.5, 0.2) is False


def test_epss_spike_needs_previous_value():
    # First time we see a CVE (no previous) → can't be a spike.
    assert is_epss_spike({"epss_score": 0.9, "epss_previous": None}, 0.5, 0.2) is False
    assert is_epss_spike({"epss_score": None, "epss_previous": 0.1}, 0.5, 0.2) is False


def test_spike_severity_floors_at_medium_not_high():
    # Unlike KEV, a spike is probability not confirmed exploitation → no high floor.
    assert _severity_spike({"cvss_severity": None}) == "medium"
    assert _severity_spike({"cvss_severity": "critical"}) == "critical"


def test_presentation_differs_by_reason():
    intel = {"epss_score": 0.7, "epss_previous": 0.4, "cvss_severity": "high"}
    spike = _presentation("CVE-2024-1", "nginx 1.18.0", intel, "epss_spike")
    kev = _presentation("CVE-2024-1", "nginx 1.18.0", {"cvss_severity": "high"}, "kev_added")

    assert spike["exploitability"] == "high"
    assert "rising exploitation risk" in spike["title"]
    assert "70%" in spike["description"] and "40%" in spike["description"]

    assert kev["exploitability"] == "active"
    assert "actively exploited" in kev["title"]


# ── match_exposures ────────────────────────────────────────────────────────────

def test_matches_inventory_against_urgent_cves():
    items = [{"asset_id": "a1", "product": "nginx", "version": "1.18.0"}]
    urgent = {"CVE-2023-44487": {"cvss_severity": "high"}}
    correlate = _correlator({("nginx", "1.18.0"): ["CVE-2023-44487", "CVE-2020-0000"]})

    out = match_exposures(items, urgent, correlate, set())

    assert len(out) == 1
    item, cve_id, intel = out[0]
    assert cve_id == "CVE-2023-44487"      # only the urgent one is returned
    assert item["asset_id"] == "a1"
    assert intel["cvss_severity"] == "high"


def test_ignores_non_urgent_cves():
    items = [{"asset_id": "a1", "product": "nginx", "version": "1.18.0"}]
    urgent = {"CVE-9999-0001": {}}  # not among the product's CVEs
    correlate = _correlator({("nginx", "1.18.0"): ["CVE-2020-1111"]})

    assert match_exposures(items, urgent, correlate, set()) == []


def test_skips_already_alerted_pairs():
    items = [{"asset_id": "a1", "product": "nginx", "version": "1.18.0"}]
    urgent = {"CVE-2023-44487": {"cvss_severity": "high"}}
    correlate = _correlator({("nginx", "1.18.0"): ["CVE-2023-44487"]})
    already = {("a1", "CVE-2023-44487")}

    assert match_exposures(items, urgent, correlate, already) == []


def test_dedups_within_a_single_run_and_mutates_already():
    # Same software on two assets → two distinct alerts; the same (asset, cve) only once.
    items = [
        {"asset_id": "a1", "product": "nginx", "version": "1.18.0"},
        {"asset_id": "a2", "product": "nginx", "version": "1.18.0"},
        {"asset_id": "a1", "product": "nginx", "version": "1.18.0"},  # duplicate row
    ]
    urgent = {"CVE-2023-44487": {"cvss_severity": "high"}}
    correlate = _correlator({("nginx", "1.18.0"): ["CVE-2023-44487"]})
    already: set = set()

    out = match_exposures(items, urgent, correlate, already)

    assert {(i["asset_id"], c) for i, c, _ in out} == {
        ("a1", "CVE-2023-44487"),
        ("a2", "CVE-2023-44487"),
    }
    assert already == {("a1", "CVE-2023-44487"), ("a2", "CVE-2023-44487")}


def test_correlates_each_software_once():
    # Two assets share the same software → correlate_fn called once for it (cache).
    items = [
        {"asset_id": "a1", "product": "nginx", "version": "1.18.0"},
        {"asset_id": "a2", "product": "nginx", "version": "1.18.0"},
    ]
    urgent = {"CVE-2023-44487": {"cvss_severity": "high"}}
    correlate = _correlator({("nginx", "1.18.0"): ["CVE-2023-44487"]})

    match_exposures(items, urgent, correlate, set())

    assert correlate.calls.count(("nginx", "1.18.0")) == 1
