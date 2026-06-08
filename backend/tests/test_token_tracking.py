from unittest.mock import MagicMock, patch
import pytest
from backend.agents.base import BaseAgent
from backend.agents.state import ScanState, AssetInfo
from backend.agents.pipeline import run_pipeline
from backend.api.metrics import get_token_metrics


class MockAgent(BaseAgent):
    agent_type = "recon"
    
    def run(self, state: ScanState) -> ScanState:
        # Simulate calling LLM during agent execution
        self.call_llm("System Prompt", "User Content")
        return state


def test_base_agent_token_tracking():
    # Mocking client to return mock completions
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Response content"
    mock_response.usage = MagicMock()
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 20
    
    with patch("backend.agents.base._client.chat.completions.create", return_value=mock_response):
        agent = MockAgent()
        assert agent.tokens_used == 0
        assert agent.model_used is None
        
        text, tokens = agent.call_llm("sys", "user")
        
        assert text == "Response content"
        assert tokens == 30
        assert agent.tokens_used == 30
        assert agent.model_used is not None


@patch("backend.agents.pipeline.supabase")
def test_pipeline_saves_tokens_and_model(mock_supabase):
    # Setup mock supabase structure
    mock_table = MagicMock()
    mock_supabase.table.return_value = mock_table
    
    # Mock for insert/update chain
    mock_insert_res = MagicMock()
    mock_insert_res.execute.return_value = MagicMock(data=[{"id": "run-123"}])
    mock_table.insert.return_value = mock_insert_res
    
    mock_update_res = MagicMock()
    mock_update_res.eq.return_value.execute.return_value = MagicMock()
    mock_table.update.return_value = mock_update_res
    
    # Run pipeline with state
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
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Mocked reply"
    mock_response.usage = MagicMock()
    mock_response.usage.prompt_tokens = 50
    mock_response.usage.completion_tokens = 50
    
    with patch("backend.agents.base._client.chat.completions.create", return_value=mock_response):
        # We only want to run one agent for testing pipeline integration
        with patch("backend.agents.pipeline.AGENT_SEQUENCE", [MockAgent]):
            run_pipeline(state)
            
    # Verify agent runs start and complete updates
    mock_table.insert.assert_any_call({
        "org_id": "org-1",
        "scan_id": "scan-1",
        "agent_type": "recon",
        "status": "running",
        "started_at": pytest.any()
    })
    
    # Check that update is called with correct tokens_used and model_used
    mock_table.update.assert_any_call({
        "status": "completed",
        "error_message": None,
        "completed_at": pytest.any(),
        "tokens_used": 100,
        "model_used": pytest.any()
    })


class FakeRunsQuery:
    def __init__(self, data):
        self.data = data
        self.filters = {}

    def select(self, _columns):
        return self

    def eq(self, column, value):
        self.filters[column] = value
        return self

    def gte(self, column, value):
        self.filters[column + "_gte"] = value
        return self

    def order(self, column, desc=False):
        return self

    def execute(self):
        # Filter data based on org_id
        filtered = [
            row for row in self.data
            if row.get("org_id") == self.filters.get("org_id")
        ]
        class Result:
            def __init__(self, d):
                self.data = d
        return Result(filtered)


class FakeMetricsDb:
    def __init__(self, data):
        self.data = data

    def table(self, table_name):
        assert table_name == "agent_runs"
        return FakeRunsQuery(self.data)


@pytest.mark.asyncio
async def test_get_token_metrics():
    test_runs = [
        {
            "org_id": "org-1",
            "agent_type": "recon",
            "status": "completed",
            "tokens_used": 150,
            "model_used": "gpt-4",
            "started_at": "2026-06-05T12:00:00Z"
        },
        {
            "org_id": "org-1",
            "agent_type": "analyst",
            "status": "completed",
            "tokens_used": 250,
            "model_used": "claude-3",
            "started_at": "2026-06-05T12:30:00Z"
        },
        {
            "org_id": "org-2", # Other organization run
            "agent_type": "recon",
            "status": "completed",
            "tokens_used": 500,
            "model_used": "gpt-4",
            "started_at": "2026-06-05T12:00:00Z"
        }
    ]
    db = FakeMetricsDb(test_runs)
    user = {"id": "user-1", "org_id": "org-1"}
    
    result = await get_token_metrics(days=30, user=user, db=db)
    
    assert result["total_tokens"] == 400
    assert result["by_agent"] == {"recon": 150, "analyst": 250}
    assert result["by_model"] == {"gpt-4": 150, "claude-3": 250}
    assert len(result["daily_usage"]) == 1
    assert result["daily_usage"][0]["date"] == "2026-06-05"
    assert result["daily_usage"][0]["tokens"] == 400


@patch("backend.agents.pipeline.supabase")
def test_pipeline_db_start_failure_handles_error_cleanly(mock_supabase):
    # Setup mock supabase structure to raise an exception on insert (simulating DB failure)
    mock_table = MagicMock()
    mock_supabase.table.return_value = mock_table
    mock_table.insert.side_effect = Exception("DB Connection Failed")
    
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
    
    # Running the pipeline with a failing DB start should handle the error cleanly
    # and not raise UnboundLocalError.
    with patch("backend.agents.pipeline.AGENT_SEQUENCE", [MockAgent]):
        res_state = run_pipeline(state)
        
    assert any("DB Connection Failed" in err for err in res_state.errors)


def test_call_llm_json_accumulates_tokens_on_retry_real_calls():
    # Mock OpenAI completions create
    mock_response_1 = MagicMock()
    mock_response_1.choices = [MagicMock()]
    mock_response_1.choices[0].message.content = "Invalid JSON"
    mock_response_1.usage = MagicMock()
    mock_response_1.usage.prompt_tokens = 10
    mock_response_1.usage.completion_tokens = 15

    mock_response_2 = MagicMock()
    mock_response_2.choices = [MagicMock()]
    mock_response_2.choices[0].message.content = '{"key": "value"}'
    mock_response_2.usage = MagicMock()
    mock_response_2.usage.prompt_tokens = 15
    mock_response_2.usage.completion_tokens = 20

    with patch("backend.agents.base._client.chat.completions.create", side_effect=[mock_response_1, mock_response_2]):
        agent = MockAgent()
        result, tokens = agent.call_llm_json("sys", "user", retries=2)
        
        assert result == {"key": "value"}
        assert tokens == 60
        assert agent.tokens_used == 60


def test_call_llm_json_accumulates_tokens_on_complete_failure():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Invalid JSON"
    mock_response.usage = MagicMock()
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 15

    with patch("backend.agents.base._client.chat.completions.create", return_value=mock_response):
        agent = MockAgent()
        with pytest.raises(ValueError):
            agent.call_llm_json("sys", "user", retries=2)
        
        # retries=2 means 3 attempts total (0, 1, 2)
        assert agent.tokens_used == 75 # (10 + 15) * 3

