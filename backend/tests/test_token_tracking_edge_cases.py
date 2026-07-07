import pytest
from unittest.mock import MagicMock, patch
from backend.agents.state import ScanState, AssetInfo
from backend.agents.pipeline import run_pipeline
from backend.api.metrics import get_token_metrics
from backend.tests.test_token_tracking import MockAgent, FakeMetricsDb


# 1. Test LLM token tracking with zero token usage (usage is None)
def test_base_agent_zero_token_usage():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Zero tokens response"
    mock_response.usage = None  # Simulate no usage metadata returned
    
    with patch("backend.agents.base._client.chat.completions.create", return_value=mock_response):
        agent = MockAgent()
        assert agent.tokens_used == 0
        
        text, tokens = agent.call_llm("sys", "user")
        
        assert text == "Zero tokens response"
        assert tokens == 0
        assert agent.tokens_used == 0


# 2. Test LLM token tracking with different models
def test_base_agent_different_models():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Model response"
    mock_response.usage = MagicMock()
    mock_response.usage.prompt_tokens = 5
    mock_response.usage.completion_tokens = 5
    
    with patch("backend.agents.base._client.chat.completions.create", return_value=mock_response):
        agent = MockAgent()
        # Override default model
        agent.model = "custom-llm-model-9000"
        
        text, tokens = agent.call_llm("sys", "user")
        
        assert tokens == 10
        assert agent.model_used == "custom-llm-model-9000"


# 3. Test metrics API with empty database response
@pytest.mark.asyncio
async def test_get_token_metrics_empty():
    db = FakeMetricsDb([])
    user = {"id": "user-1", "org_id": "org-1"}
    
    result = await get_token_metrics(days=30, user=user, db=db)
    
    assert result["total_tokens"] == 0
    assert result["by_agent"] == {}
    assert result["by_model"] == {}
    assert result["daily_usage"] == []


# 4. Test database insertion failure in pipeline (_log_agent_start fails)
@patch("backend.agents.pipeline.supabase")
def test_pipeline_db_insertion_failure(mock_supabase):
    mock_table = MagicMock()
    mock_supabase.table.return_value = mock_table
    
    # Simulate DB insertion failure (e.g. Postgres / Supabase connection error)
    mock_table.insert.side_effect = Exception("Database insertion failed")
    
    state = ScanState(
        scan_id="scan-1",
        org_id="org-1",
        asset=AssetInfo(
            id="asset-1",
            name="Test Asset",
            host="localhost",
            type="website",
            is_internal=True
        ),
        permission_rules=[]
    )
    
    with patch("backend.agents.pipeline.AGENT_SEQUENCE", [MockAgent]):
        # Run the pipeline, which should handle the DB insertion failure cleanly
        # and append it to state.errors rather than crashing.
        res_state = run_pipeline(state)
        
        assert any("Database insertion failed" in err for err in res_state.errors)

