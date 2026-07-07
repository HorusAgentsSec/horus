"""
A finding a human previously marked "resolved" that a new scan detects again is a regression,
not still-fixed. Without _reopen_resolved_reappearances, the upsert in _persist_finding never
touches the status column, so it would stay hidden as "resolved" in the default findings view
even though the vulnerability is back. This guards the reopen + raw_data flag.
"""

from unittest.mock import MagicMock

from backend.agents import pipeline
from backend.agents.state import AnalyzedFinding, AssetInfo, ScanState


def _table_with_resolved_fingerprints(resolved_fps: set[str]):
    """A fake supabase client whose `findings` table reports the given fingerprints as
    already-resolved for the .select(...).eq(...).eq(...).in_(...) reappearance check, and
    records every .update(...) call for assertions."""
    mock = MagicMock()
    updates = []

    def table(name):
        t = MagicMock()
        if name == "findings":
            select_chain = t.select.return_value.eq.return_value.eq.return_value.in_.return_value
            select_chain.execute.return_value.data = [{"fingerprint": fp} for fp in resolved_fps]

            def record_update(payload):
                updates.append(payload)
                return t.update.return_value
            t.update.side_effect = record_update
            t.update.return_value.eq.return_value.eq.return_value.in_.return_value.execute.return_value = None
        return t

    mock.table.side_effect = table
    return mock, updates


def test_reopens_findings_that_were_resolved_and_reappeared(monkeypatch):
    mock_supabase, updates = _table_with_resolved_fingerprints({"fp-1"})
    monkeypatch.setattr(pipeline, "supabase", mock_supabase)

    reappeared = pipeline._reopen_resolved_reappearances("org-1", ["fp-1", "fp-2"])

    assert reappeared == {"fp-1"}
    assert len(updates) == 1
    assert updates[0] == {"status": "open"}


def test_no_reopen_when_nothing_was_resolved(monkeypatch):
    mock_supabase, updates = _table_with_resolved_fingerprints(set())
    monkeypatch.setattr(pipeline, "supabase", mock_supabase)

    reappeared = pipeline._reopen_resolved_reappearances("org-1", ["fp-1"])

    assert reappeared == set()
    assert updates == []


def test_empty_fingerprint_list_short_circuits_without_a_query(monkeypatch):
    mock_supabase = MagicMock()
    monkeypatch.setattr(pipeline, "supabase", mock_supabase)

    assert pipeline._reopen_resolved_reappearances("org-1", []) == set()
    mock_supabase.table.assert_not_called()


def test_db_failure_degrades_to_no_reappearances(monkeypatch):
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.select.return_value.eq.return_value.eq.return_value.in_.return_value.execute.side_effect = RuntimeError(
        "db down"
    )
    monkeypatch.setattr(pipeline, "supabase", mock_supabase)

    assert pipeline._reopen_resolved_reappearances("org-1", ["fp-1"]) == set()


def _state_with_finding(fp="fp-1"):
    finding = AnalyzedFinding(id=fp, title="t", description="d", severity="high", confidence=0.8, rationale="r")
    state = ScanState(
        scan_id="scan-1", org_id="org-1",
        asset=AssetInfo(id="a", name="n", host="h", type="domain", is_internal=True),
        analyzed_findings=[finding],
    )
    return state, finding


def test_persist_finding_flags_reappeared_in_raw_data(monkeypatch):
    mock_supabase = MagicMock()
    monkeypatch.setattr(pipeline, "supabase", mock_supabase)
    state, finding = _state_with_finding()

    pipeline._persist_finding(state, finding, set(), reappeared=True)

    upserted = mock_supabase.table.return_value.upsert.call_args[0][0]
    assert "reappeared_at" in upserted["raw_data"]


def test_persist_finding_omits_reappeared_flag_by_default(monkeypatch):
    mock_supabase = MagicMock()
    monkeypatch.setattr(pipeline, "supabase", mock_supabase)
    state, finding = _state_with_finding()

    pipeline._persist_finding(state, finding, set())

    upserted = mock_supabase.table.return_value.upsert.call_args[0][0]
    assert "reappeared_at" not in upserted["raw_data"]
    assert "status" not in upserted  # the upsert must never clobber a human-set status
