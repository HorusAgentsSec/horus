"""
Tests for BreachDirectory.org API integration.
"""

import pytest
import httpx
from unittest.mock import patch, MagicMock

from backend.core import breach_directory


class TestBreachDirectoryCheckEmail:
    """Tests for check_email()"""

    def test_no_api_key_raises_valueerror(self):
        """Should raise ValueError if API key is not configured."""
        with pytest.raises(ValueError, match="API key not configured"):
            breach_directory.check_email("test@example.com", "")

        with pytest.raises(ValueError, match="API key not configured"):
            breach_directory.check_email("test@example.com", "   ")

    def test_email_found_in_breaches(self):
        """Should return found=True and list sources when email is in breaches."""
        mock_response = {
            "found": True,
            "result": [
                {
                    "sha1": "e99a18c428cb38d5f260853678922e03d4b435f3",
                    "sources": [
                        {
                            "name": "LinkedIn",
                            "date": "2021-06-22",
                            "entries": 1,
                        },
                        {
                            "name": "Adobe",
                            "date": "2013-10-04",
                            "entries": 1,
                        },
                    ],
                }
            ],
        }

        with patch("httpx.Client") as mock_client_ctx:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 200
            mock_response_obj.json.return_value = mock_response
            mock_client.get.return_value = mock_response_obj
            mock_client_ctx.return_value.__enter__.return_value = mock_client

            result = breach_directory.check_email("test@example.com", "test_api_key")

            assert result["found"] is True
            assert len(result["sources"]) == 2
            assert result["sources"][0]["name"] == "LinkedIn"
            assert result["sources"][0]["date"] == "2021-06-22"
            assert result["sources"][0]["count"] == 1
            assert result["sha1_hash"] == "e99a18c428cb38d5f260853678922e03d4b435f3"

    def test_email_not_found(self):
        """Should return found=False when email is not in any breach."""
        mock_response = {
            "found": False,
            "result": [],
        }

        with patch("httpx.Client") as mock_client_ctx:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 200
            mock_response_obj.json.return_value = mock_response
            mock_client.get.return_value = mock_response_obj
            mock_client_ctx.return_value.__enter__.return_value = mock_client

            result = breach_directory.check_email("clean@example.com", "test_api_key")

            assert result["found"] is False
            assert result["sources"] == []
            assert result["sha1_hash"] is None

    def test_404_response_returns_not_found(self):
        """Should treat 404 as not found gracefully."""
        with patch("httpx.Client") as mock_client_ctx:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 404
            mock_client.get.return_value = mock_response_obj
            mock_client_ctx.return_value.__enter__.return_value = mock_client

            result = breach_directory.check_email("test@example.com", "test_api_key")

            assert result["found"] is False
            assert result["sources"] == []

    def test_401_invalid_api_key(self):
        """Should raise ValueError on invalid API key (401)."""
        with patch("httpx.Client") as mock_client_ctx:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 401
            mock_response_obj.raise_for_status.side_effect = httpx.HTTPStatusError(
                "401", request=MagicMock(), response=mock_response_obj
            )
            mock_client.get.return_value = mock_response_obj
            mock_client_ctx.return_value.__enter__.return_value = mock_client

            with pytest.raises(ValueError, match="invalid or expired"):
                breach_directory.check_email("test@example.com", "bad_key")

    def test_429_rate_limit(self):
        """Should raise ValueError on rate limit (429)."""
        with patch("httpx.Client") as mock_client_ctx:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 429
            mock_response_obj.raise_for_status.side_effect = httpx.HTTPStatusError(
                "429", request=MagicMock(), response=mock_response_obj
            )
            mock_client.get.return_value = mock_response_obj
            mock_client_ctx.return_value.__enter__.return_value = mock_client

            with pytest.raises(ValueError, match="rate limit"):
                breach_directory.check_email("test@example.com", "test_api_key")


class TestBreachDirectoryCheckDomain:
    """Tests for check_domain()"""

    def test_domain_search_same_as_email(self):
        """Should support domain searches with the same response normalization."""
        mock_response = {
            "found": True,
            "result": [
                {
                    "sha1": None,
                    "sources": [
                        {
                            "name": "BreachCompilation",
                            "date": "2022-01-01",
                            "entries": 50,
                        },
                    ],
                }
            ],
        }

        with patch("httpx.Client") as mock_client_ctx:
            mock_client = MagicMock()
            mock_response_obj = MagicMock()
            mock_response_obj.status_code = 200
            mock_response_obj.json.return_value = mock_response
            mock_client.get.return_value = mock_response_obj
            mock_client_ctx.return_value.__enter__.return_value = mock_client

            result = breach_directory.check_domain("example.com", "test_api_key")

            assert result["found"] is True
            assert len(result["sources"]) == 1
            assert result["sources"][0]["name"] == "BreachCompilation"
            assert result["sources"][0]["count"] == 50

    def test_domain_no_api_key(self):
        """Should raise ValueError for domain check without API key."""
        with pytest.raises(ValueError, match="API key not configured"):
            breach_directory.check_domain("example.com", "")
