"""Posture PDF report — verifies the board one-pager builds for full, single-point and empty
timelines. Pure (no backend), like test_posture.py."""

from backend.core.posture_report import build_posture_pdf


def _timeline(n: int) -> list[dict]:
    return [
        {
            "date": f"2026-05-{d:02d}",
            "risk_score": 50 - d,
            "open_findings": 12 - d,
            "kev_active": 1 if d % 3 == 0 else 0,
            "critical": 2,
            "high": 3,
            "medium": 4,
            "low": 1,
            "info": 0,
        }
        for d in range(1, n + 1)
    ]


def _is_pdf(b: bytes) -> bool:
    return b[:5] == b"%PDF-" and len(b) > 1000


def test_full_timeline_builds_pdf():
    tl = _timeline(30)
    report = {
        "org_name": "Acme Corp",
        "days": 90,
        "timeline": tl,
        "current": tl[-1],
        "trend_delta": tl[-1]["risk_score"] - tl[0]["risk_score"],  # negative = improved
    }
    assert _is_pdf(build_posture_pdf(report))


def test_single_point_builds_pdf():
    tl = _timeline(1)
    report = {"org_name": "Solo", "days": 30, "timeline": tl, "current": tl[0], "trend_delta": 0}
    assert _is_pdf(build_posture_pdf(report))


def test_rising_risk_builds_pdf():
    tl = _timeline(5)
    tl[-1]["risk_score"] = tl[0]["risk_score"] + 20  # risk went up
    report = {"org_name": "Up Inc", "days": 14, "timeline": tl, "current": tl[-1],
              "trend_delta": 20}
    assert _is_pdf(build_posture_pdf(report))


def test_empty_history_builds_pdf():
    report = {"org_name": None, "days": 90, "timeline": [], "current": None, "trend_delta": 0}
    assert _is_pdf(build_posture_pdf(report))
