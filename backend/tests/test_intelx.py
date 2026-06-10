"""Tests for IntelligenceX dark web search integration."""

import pytest
from unittest.mock import MagicMock, patch

from backend.core.intelx import search, is_darkweb_result


class TestIsDarkwebResult:
    """Test is_darkweb_result detection."""

    def test_darkweb_bucket(self):
        record = {"bucket": "darkweb", "name": "test"}
        assert is_darkweb_result(record) is True

    def test_leaks_bucket(self):
        record = {"bucket": "leaks", "name": "test"}
        assert is_darkweb_result(record) is True

    def test_pastes_bucket(self):
        record = {"bucket": "pastes", "name": "test"}
        assert is_darkweb_result(record) is True

    def test_tor_bucket(self):
        record = {"bucket": "tor", "name": "test"}
        assert is_darkweb_result(record) is True

    def test_i2p_bucket(self):
        record = {"bucket": "i2p", "name": "test"}
        assert is_darkweb_result(record) is True

    def test_onion_bucket(self):
        record = {"bucket": "onion_forum", "name": "test"}
        assert is_darkweb_result(record) is True

    def test_regular_source_bucket(self):
        record = {"bucket": "public_documents", "name": "test"}
        assert is_darkweb_result(record) is False

    def test_empty_bucket(self):
        record = {"bucket": "", "name": "test"}
        assert is_darkweb_result(record) is False

    def test_missing_bucket(self):
        record = {"name": "test"}
        assert is_darkweb_result(record) is False


class TestSearch:
    """Test IntelligenceX search function."""

    def test_search_no_api_key(self):
        """Should raise ValueError if API key is empty."""
        with pytest.raises(ValueError, match="API key not configured"):
            search("example.com", "", max_results=10)

    @patch("backend.core.intelx.httpx.Client")
    def test_search_happy_path(self, mock_client_class):
        """Test successful search with 2 records."""
        # Mock the POST response (initiate search)
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {"id": "search_123", "status": 0}

        # Mock the GET response (poll results)
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "status": 2,
            "records": [
                {
                    "name": "example.com found on Pastebin",
                    "date": "2026-06-10",
                    "bucket": "pastes",
                },
                {
                    "name": "example.com in dark web forum",
                    "date": "2026-06-09",
                    "bucket": "darkweb",
                },
            ],
        }

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_post_response
        mock_client.get.return_value = mock_get_response
        mock_client_class.return_value = mock_client

        results = search("example.com", "test_key", max_results=10)

        assert len(results) == 2
        assert results[0]["source"] == "intelx"
        assert results[0]["bucket"] == "pastes"
        assert results[1]["bucket"] == "darkweb"

    @patch("backend.core.intelx.httpx.Client")
    def test_search_invalid_api_key(self, mock_client_class):
        """Test API key validation (401)."""
        mock_response = MagicMock()
        mock_response.status_code = 401

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        results = search("example.com", "invalid_key", max_results=10)

        assert results == []

    @patch("backend.core.intelx.httpx.Client")
    def test_search_rate_limit(self, mock_client_class):
        """Test rate limit handling (402)."""
        mock_response = MagicMock()
        mock_response.status_code = 402

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        results = search("example.com", "test_key", max_results=10)

        assert results == []

    @patch("backend.core.intelx.time.sleep")
    @patch("backend.core.intelx.time.time")
    @patch("backend.core.intelx.httpx.Client")
    def test_search_timeout(self, mock_client_class, mock_time, mock_sleep):
        """Test timeout handling after max polls."""
        # Simulate time advancing past timeout
        time_values = [0, 2, 4, 6, 40]  # Last value > 30s timeout
        mock_time.side_effect = time_values

        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {"id": "search_123", "status": 0}

        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            "status": 1,  # Not complete
            "records": [],
        }

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_post_response
        mock_client.get.return_value = mock_get_response
        mock_client_class.return_value = mock_client

        results = search("example.com", "test_key", max_results=10)

        # Should return empty list after timeout
        assert results == []
