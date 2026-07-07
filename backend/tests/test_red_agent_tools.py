"""
Tests for RedAgent's tool executor (backend/agents/red_agent.py::_build_executor).

save_attack_chain reuses the red_findings table (category="attack_chain") instead of a
dedicated table — a chain has no single asset_id, so the asset list and step breakdown go
into the existing free-form `evidence` jsonb column. This guards that shape.
"""

from unittest.mock import MagicMock

import backend.agents.red_agent as red_agent_module
from backend.agents.red_agent import _build_executor


def _executor(monkeypatch, mock_supabase):
    # The tool closures look up the module-level `supabase` name at call time, so the patch
    # must still be active when the test invokes them — monkeypatch restores it at test
    # teardown, after those calls happen (unlike a manual try/finally around _build_executor,
    # which would restore it too early and leave the closures pointed at conftest's stub).
    monkeypatch.setattr(red_agent_module, "supabase", mock_supabase)
    return _build_executor(org_id="org-1", run_id="run-1")


def test_save_attack_chain_persists_multi_asset_evidence(monkeypatch):
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.insert.return_value.execute.return_value.data = [{"id": "chain-1"}]
    tools = _executor(monkeypatch, mock_supabase)

    result = tools["save_attack_chain"](
        title="Leaked credential unlocks admin panel",
        narrative="Cred breach on asset A logs into the exposed admin panel on asset B.",
        severity="critical",
        asset_ids=["asset-a", "asset-b"],
        steps=[{"asset_id": "asset-a", "weakness": "credential breach"},
               {"asset_id": "asset-b", "weakness": "exposed admin panel"}],
    )

    assert result == {"saved": True, "id": "chain-1"}
    inserted = mock_supabase.table.return_value.insert.call_args[0][0]
    assert inserted["category"] == "attack_chain"
    assert inserted["org_id"] == "org-1"
    assert inserted["run_id"] == "run-1"
    assert "asset_id" not in inserted  # no single asset applies to a cross-asset chain
    assert inserted["evidence"]["asset_ids"] == ["asset-a", "asset-b"]
    assert len(inserted["evidence"]["steps"]) == 2


def test_save_attack_chain_defaults_steps_to_empty_list(monkeypatch):
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.insert.return_value.execute.return_value.data = [{"id": "chain-2"}]
    tools = _executor(monkeypatch, mock_supabase)

    tools["save_attack_chain"](
        title="t", narrative="n", severity="high", asset_ids=["a"],
    )

    inserted = mock_supabase.table.return_value.insert.call_args[0][0]
    assert inserted["evidence"]["steps"] == []


def test_save_attack_chain_returns_error_on_db_failure(monkeypatch):
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.insert.return_value.execute.side_effect = RuntimeError("db down")
    tools = _executor(monkeypatch, mock_supabase)

    result = tools["save_attack_chain"](
        title="t", narrative="n", severity="high", asset_ids=["a"],
    )
    assert result == {"saved": False, "error": "db down"}


def test_save_red_finding_still_uses_single_asset_id(monkeypatch):
    # Regression check: adding save_attack_chain must not change save_red_finding's shape.
    mock_supabase = MagicMock()
    mock_supabase.table.return_value.insert.return_value.execute.return_value.data = [{"id": "f-1"}]
    tools = _executor(monkeypatch, mock_supabase)

    tools["save_red_finding"](
        title="Exposed .git directory", description="d", severity="high",
        category="exposed_path", asset_id="asset-a",
    )
    inserted = mock_supabase.table.return_value.insert.call_args[0][0]
    assert inserted["asset_id"] == "asset-a"
    assert inserted["category"] == "exposed_path"
