"""
Tests for the job-history context manager (core.jobs.job_run).

Verifies the control flow — completed vs failed, the detail dict is passed through, exceptions are
re-raised — and that a logging failure (no job id) never blocks the wrapped work.
"""

import pytest

from backend.core import jobs


@pytest.fixture
def capture(monkeypatch):
    calls = {"start": [], "finish": []}
    monkeypatch.setattr(jobs, "_insert_running",
                        lambda jt, org, ref, trig: calls["start"].append((jt, org, ref, trig)) or "job-1")
    monkeypatch.setattr(jobs, "_finish",
                        lambda jid, status, detail, started, error: calls["finish"].append(
                            {"id": jid, "status": status, "detail": dict(detail), "error": error}))
    return calls


def test_successful_run_records_completed_with_detail(capture):
    with jobs.job_run(jobs.CVE_SYNC) as d:
        d["rows"] = 42

    assert capture["start"] == [("cve_sync", None, None, "cron")]
    assert len(capture["finish"]) == 1
    fin = capture["finish"][0]
    assert fin["status"] == "completed"
    assert fin["detail"] == {"rows": 42}
    assert fin["error"] is None


def test_failed_run_records_failed_and_reraises(capture):
    with pytest.raises(ValueError, match="boom"):
        with jobs.job_run(jobs.WATCHTOWER, org_id="o1", ref_id="r1", trigger="manual") as d:
            d["partial"] = True
            raise ValueError("boom")

    assert capture["start"] == [("watchtower", "o1", "r1", "manual")]
    fin = capture["finish"][0]
    assert fin["status"] == "failed"
    assert fin["error"] == "boom"
    assert fin["detail"] == {"partial": True}


def test_logging_failure_does_not_block_work(monkeypatch):
    # _insert_running returns None (e.g. table missing) → no finish call, but the body still runs.
    monkeypatch.setattr(jobs, "_insert_running", lambda *a: None)
    finished = []
    monkeypatch.setattr(jobs, "_finish", lambda *a, **k: finished.append(a))

    ran = []
    with jobs.job_run(jobs.DISCOVERY) as d:
        ran.append(True)
        d["x"] = 1

    assert ran == [True]
    assert finished == []  # no job id → nothing to finish, and no crash
