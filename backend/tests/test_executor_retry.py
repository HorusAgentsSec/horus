"""
Tests for scheduled-scan auto-retry (core.executor._run_scan_safe).

A failed scheduled scan should reset to pending and requeue with one fewer retry; a successful or
canceled scan should not retry; and retries should stop at zero.
"""

import types

import pytest

from backend.core import executor
from backend.agents import pipeline


class _FakeTable:
    def __init__(self, sink): self.sink = sink; self._update = None
    def update(self, payload): self._update = payload; return self
    def eq(self, *a, **k): return self
    def execute(self):
        if self._update is not None:
            self.sink.append(self._update)
        return types.SimpleNamespace(data=[])


class _FakeSupabase:
    def __init__(self): self.updates = []
    def table(self, _): return _FakeTable(self.updates)


def _state(errors, canceled=False):
    return types.SimpleNamespace(errors=errors, canceled=canceled)


@pytest.fixture
def wired(monkeypatch):
    fake = _FakeSupabase()
    monkeypatch.setattr(executor, "supabase", fake)
    requeued = []
    monkeypatch.setattr(executor, "submit_scan",
                        lambda sid, org, retries_left=0: requeued.append((sid, org, retries_left)))
    return fake, requeued


def test_failed_scan_resets_to_pending_and_requeues(wired, monkeypatch):
    fake, requeued = wired
    monkeypatch.setattr(pipeline, "run_pipeline_for_scan", lambda s, o: _state(["analyst: boom"]))

    executor._run_scan_safe("scan-1", "org-1", retries_left=1)

    assert requeued == [("scan-1", "org-1", 0)]            # requeued with one fewer retry
    assert any(u.get("status") == "pending" for u in fake.updates)  # reset to pending


def test_successful_scan_does_not_retry(wired, monkeypatch):
    _, requeued = wired
    monkeypatch.setattr(pipeline, "run_pipeline_for_scan", lambda s, o: _state([]))
    executor._run_scan_safe("scan-2", "org-1", retries_left=1)
    assert requeued == []


def test_canceled_scan_does_not_retry(wired, monkeypatch):
    _, requeued = wired
    monkeypatch.setattr(pipeline, "run_pipeline_for_scan",
                        lambda s, o: _state(["canceled"], canceled=True))
    executor._run_scan_safe("scan-3", "org-1", retries_left=2)
    assert requeued == []


def test_no_retries_left_stops(wired, monkeypatch):
    _, requeued = wired
    monkeypatch.setattr(pipeline, "run_pipeline_for_scan", lambda s, o: _state(["boom"]))
    executor._run_scan_safe("scan-4", "org-1", retries_left=0)
    assert requeued == []


def test_crash_with_retry_requeues(wired, monkeypatch):
    fake, requeued = wired
    def boom(s, o): raise RuntimeError("provider down")
    monkeypatch.setattr(pipeline, "run_pipeline_for_scan", boom)

    executor._run_scan_safe("scan-5", "org-1", retries_left=1)

    assert requeued == [("scan-5", "org-1", 0)]
    # marked failed (on crash) then reset to pending for the retry
    assert any(u.get("status") == "failed" for u in fake.updates)
    assert any(u.get("status") == "pending" for u in fake.updates)
