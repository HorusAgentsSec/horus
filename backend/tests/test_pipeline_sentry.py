"""
An agent exception in run_pipeline is caught and logged (the pipeline continues to the next
agent) rather than raised, so it would never reach Sentry's automatic FastAPI/Starlette capture.
This test guards the explicit sentry_sdk.capture_exception(e) call added at that catch site.
"""

from unittest.mock import MagicMock, patch

from backend.agents.base import BaseAgent
from backend.agents.pipeline import run_pipeline
from backend.agents.state import AssetInfo, ScanState


class _BoomAgent(BaseAgent):
    agent_type = "recon"

    def run(self, state: ScanState) -> ScanState:
        raise RuntimeError("boom")


@patch("backend.agents.pipeline.supabase", new_callable=MagicMock)
def test_agent_exception_is_reported_to_sentry(mock_supabase):
    mock_supabase.table.return_value.insert.return_value.execute.return_value = MagicMock(
        data=[{"id": "run-1"}]
    )
    state = ScanState(
        scan_id="scan-1",
        org_id="org-1",
        asset=AssetInfo(id="a", name="n", host="h", type="domain", is_internal=True),
        permission_rules=[],
    )
    with patch("backend.agents.pipeline.AGENT_SEQUENCE", [_BoomAgent]), \
         patch("sentry_sdk.capture_exception") as mock_capture:
        result = run_pipeline(state)

    assert any("boom" in e for e in result.errors)
    mock_capture.assert_called_once()
    assert isinstance(mock_capture.call_args[0][0], RuntimeError)
