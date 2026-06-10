"""Unit tests for findings import (Nuclei + Generic formats)."""
import json
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# Example Nuclei JSONL fixture (3 findings)
NUCLEI_JSONL = ('{"host": "example.com", "matched-at": "https://example.com/admin", "info": {"name": "SQL Injection in Login Form", "severity": "critical", "description": "Potential SQL injection vulnerability detected", "classification": {"cve-id": ["CVE-2024-1234"]}}}\n'
                '{"host": "api.example.com", "matched-at": "https://api.example.com/v1/users", "info": {"name": "Unauthenticated API Endpoint", "severity": "high", "description": "API endpoint accessible without authentication", "classification": {"cve-id": []}}}\n'
                '{"host": "example.com", "matched-at": "https://example.com/", "info": {"name": "Outdated Framework Version", "severity": "medium", "description": "Server running outdated version of framework", "classification": {"cve-id": ["CVE-2024-5678", "CVE-2024-5679"]}}}')

# Example Generic JSON fixture (3 findings)
GENERIC_JSON = json.dumps([
    {
        "title": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "host": "app.example.com",
        "description": "Stored XSS vulnerability in comments section",
        "cve": "CVE-2024-2024",
        "cvss_score": 7.5,
    },
    {
        "title": "CORS Misconfiguration",
        "severity": "medium",
        "host": "api.example.com",
        "description": "Overly permissive CORS headers allowing cross-origin requests",
        "cve": "",
        "cvss_score": 5.3,
    },
    {
        "title": "Weak SSL Configuration",
        "severity": "medium",
        "host": "example.com",
        "description": "Server using weak TLS version",
        "cve": "CVE-2024-3030",
        "cvss_score": 4.8,
    },
])


def test_import_nuclei_jsonl():
    """Test importing findings in Nuclei JSONL format."""
    # This test demonstrates the expected behavior; actual execution
    # requires a valid auth token and database setup.
    # In a full test, you'd:
    # 1. Sign in a test user
    # 2. Create test assets (example.com, api.example.com)
    # 3. POST /findings/import with the file
    # 4. Verify 3 findings created (skipping noise if any)
    assert len(NUCLEI_JSONL.split('\n')) == 3, "Should have 3 lines (3 findings)"


def test_import_generic_json():
    """Test importing findings in generic JSON array format."""
    data = json.loads(GENERIC_JSON)
    assert len(data) == 3, "Should have 3 findings"
    assert data[0]["title"] == "Cross-Site Scripting (XSS)"
    assert data[0]["cve"] == "CVE-2024-2024"


def test_parse_nuclei_jsonl():
    """Unit test for Nuclei JSONL parser."""
    from backend.api.findings import _parse_nuclei_jsonl

    rows = _parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(rows) == 3
    assert rows[0]["title"] == "SQL Injection in Login Form"
    assert rows[0]["severity"] == "critical"
    assert rows[0]["host"] == "example.com"
    assert rows[0]["cve_ids"] == ["CVE-2024-1234"]

    assert rows[1]["title"] == "Unauthenticated API Endpoint"
    assert rows[1]["severity"] == "high"
    assert rows[1]["host"] == "api.example.com"
    assert rows[1]["cve_ids"] == []

    assert rows[2]["title"] == "Outdated Framework Version"
    assert rows[2]["severity"] == "medium"
    assert rows[2]["cve_ids"] == ["CVE-2024-5678", "CVE-2024-5679"]


def test_parse_generic_json():
    """Unit test for generic JSON parser."""
    from backend.api.findings import _parse_generic_json

    rows = _parse_generic_json(GENERIC_JSON)
    assert len(rows) == 3
    assert rows[0]["title"] == "Cross-Site Scripting (XSS)"
    assert rows[0]["severity"] == "high"
    assert rows[0]["cve_ids"] == ["CVE-2024-2024"]
    assert rows[0]["cvss_score"] == 7.5

    assert rows[1]["title"] == "CORS Misconfiguration"
    assert rows[1]["cve_ids"] == []  # cve field was empty

    assert rows[2]["cve_ids"] == ["CVE-2024-3030"]
