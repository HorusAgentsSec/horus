"""
Tests for abuse.ch IOC integrations (ThreatFox + URLhaus).
"""

from unittest.mock import patch, MagicMock
import httpx

from backend.core.abuse_intel import check_threatfox, check_urlhaus


class TestThreatFox:
    """Test ThreatFox IOC lookups."""

    def test_threatfox_found(self):
        """Test successful ThreatFox lookup with results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "192.0.2.1",
                    "ioc_type": "ip:port",
                    "threat_type": "c2",
                    "malware": "emotet",
                    "malware_alias": None,
                    "confidence_level": 85,
                    "first_seen": "2024-01-15",
                    "last_seen": "2024-06-10",
                    "reference": "https://threatfox.example.com/ioc/12345",
                    "tags": ["c2", "botnet"],
                }
            ]
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_threatfox("192.0.2.1")

        assert result["found"] is True
        assert len(result["threats"]) == 1
        threat = result["threats"][0]
        assert threat["ioc_type"] == "ip:port"
        assert threat["threat_type"] == "c2"
        assert threat["malware"] == "emotet"
        assert threat["confidence_level"] == 85
        assert threat["source"] == "threatfox"

    def test_threatfox_not_found(self):
        """Test ThreatFox lookup with no results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_result",
            "data": None,
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_threatfox("8.8.8.8")

        assert result["found"] is False
        assert result["threats"] == []

    def test_threatfox_api_error(self):
        """Test ThreatFox when API returns error."""
        with patch("httpx.Client.post") as mock_post:
            mock_post.side_effect = httpx.HTTPStatusError(
                "404", request=None, response=MagicMock(status_code=404)
            )
            result = check_threatfox("invalid.example.com")

        assert result["found"] is False
        assert result["threats"] == []

    def test_threatfox_empty_term(self):
        """Test ThreatFox with empty term."""
        result = check_threatfox("")
        assert result["found"] is False
        assert result["threats"] == []

    def test_threatfox_multiple_threats(self):
        """Test ThreatFox with multiple threats for same IOC."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc_type": "domain",
                    "threat_type": "c2",
                    "malware": "emotet",
                    "confidence_level": 90,
                    "first_seen": "2024-01-15",
                    "reference": "https://threatfox.example.com/1",
                    "tags": ["c2"],
                },
                {
                    "ioc_type": "domain",
                    "threat_type": "malware_drop",
                    "malware": "trickbot",
                    "confidence_level": 75,
                    "first_seen": "2024-02-20",
                    "reference": "https://threatfox.example.com/2",
                    "tags": ["banking_malware"],
                }
            ]
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_threatfox("evil.example.com")

        assert result["found"] is True
        assert len(result["threats"]) == 2
        assert result["threats"][0]["malware"] == "emotet"
        assert result["threats"][1]["malware"] == "trickbot"


class TestURLhaus:
    """Test URLhaus malicious URL lookups."""

    def test_urlhaus_found(self):
        """Test successful URLhaus lookup with results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "islisted",
            "urls": [
                {
                    "id": 1234567,
                    "url": "http://evil.example.com/malware.exe",
                    "url_status": "online",
                    "threat": "malware",
                    "tags": ["trojan", "spyware"],
                    "date_added": "2024-05-01",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/1234567/",
                }
            ]
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_urlhaus("evil.example.com")

        assert result["found"] is True
        assert len(result["urls"]) == 1
        url = result["urls"][0]
        assert url["url"] == "http://evil.example.com/malware.exe"
        assert url["threat"] == "malware"
        assert url["url_status"] == "online"
        assert url["source"] == "urlhaus"

    def test_urlhaus_not_found(self):
        """Test URLhaus lookup with no results."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
            "urls": None,
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_urlhaus("clean.example.com")

        assert result["found"] is False
        assert result["urls"] == []

    def test_urlhaus_api_error(self):
        """Test URLhaus when API returns error."""
        with patch("httpx.Client.post") as mock_post:
            mock_post.side_effect = httpx.HTTPStatusError(
                "500", request=None, response=MagicMock(status_code=500)
            )
            result = check_urlhaus("example.com")

        assert result["found"] is False
        assert result["urls"] == []

    def test_urlhaus_empty_host(self):
        """Test URLhaus with empty host."""
        result = check_urlhaus("")
        assert result["found"] is False
        assert result["urls"] == []

    def test_urlhaus_multiple_urls(self):
        """Test URLhaus with multiple malicious URLs on same domain."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "islisted",
            "urls": [
                {
                    "url": "http://evil.example.com/malware1.exe",
                    "url_status": "online",
                    "threat": "malware",
                    "date_added": "2024-05-01",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/111/",
                },
                {
                    "url": "http://evil.example.com/malware2.exe",
                    "url_status": "offline",
                    "threat": "phishing",
                    "date_added": "2024-05-05",
                    "urlhaus_link": "https://urlhaus.abuse.ch/url/222/",
                }
            ]
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_urlhaus("evil.example.com")

        assert result["found"] is True
        assert len(result["urls"]) == 2
        assert result["urls"][0]["threat"] == "malware"
        assert result["urls"][1]["threat"] == "phishing"


class TestIOCCheckNoFalsePositives:
    """Test that legitimate IPs/domains don't trigger false positives."""

    def test_google_dns_not_found_threatfox(self):
        """Google's public DNS (8.8.8.8) should not be in ThreatFox."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_result",
            "data": None,
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_threatfox("8.8.8.8")

        assert result["found"] is False

    def test_cloudflare_dns_not_found_threatfox(self):
        """Cloudflare's public DNS (1.1.1.1) should not be in ThreatFox."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_result",
            "data": None,
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_threatfox("1.1.1.1")

        assert result["found"] is False

    def test_google_com_not_found_urlhaus(self):
        """google.com should not be in URLhaus."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
            "urls": None,
        }

        with patch("httpx.Client.post", return_value=mock_response):
            result = check_urlhaus("google.com")

        assert result["found"] is False
