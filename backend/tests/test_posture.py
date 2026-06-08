"""
Tests for posture scoring — the deterministic number behind the executive timeline.

Covers the pure `score_from_counts` (severity weighting + KEV bonus). DB access in
posture.py is lazy-imported, so importing the scorer needs no configured backend.
"""

from backend.core.posture import KEV_BONUS, WEIGHTS, is_suppressed, score_from_counts


def test_zero_when_no_findings():
    assert score_from_counts({}, 0) == 0
    assert score_from_counts({"critical": 0, "high": 0}, 0) == 0


def test_weights_are_summed_per_severity():
    counts = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    expected = (
        WEIGHTS["critical"] * 1
        + WEIGHTS["high"] * 2
        + WEIGHTS["medium"] * 3
        + WEIGHTS["low"] * 4
        + WEIGHTS["info"] * 5
    )
    assert score_from_counts(counts) == expected


def test_info_findings_do_not_move_the_score():
    assert score_from_counts({"info": 100}, 0) == 0


def test_one_critical_outweighs_several_mediums():
    assert score_from_counts({"critical": 1}) > score_from_counts({"medium": 4})


def test_kev_active_adds_bonus_on_top():
    base = score_from_counts({"high": 1})
    with_kev = score_from_counts({"high": 1}, kev_active=1)
    assert with_kev == base + KEV_BONUS


def test_handles_none_and_missing_values():
    # Defensive: counts may carry None, unknown severities are ignored.
    assert score_from_counts({"high": None, "bogus": 5}, kev_active=None) == 0


def test_is_suppressed_only_for_false_positive_verdict():
    assert is_suppressed({"verdict": "false_positive"}) is True
    assert is_suppressed({"verdict": "confirmed"}) is False
    assert is_suppressed({"verdict": "needs_verification"}) is False
    assert is_suppressed({}) is False
    assert is_suppressed(None) is False
