"""
Unit tests for CVE intelligence sync — NVD CVSS enrichment.

Covers:
  - _fetch_nvd_cvss_batch: successful v3.1 parse
  - _fetch_nvd_cvss_batch: fallback from absent v3.1 to v3.0
  - _fetch_nvd_cvss_batch: no metrics at all -> empty result
  - run_sync: calls _fetch_nvd_cvss_batch for KEV CVEs with null CVSS scores
"""

from unittest.mock import MagicMock, patch


# ── Helpers ──────────────────────────────────────────────────────────────────

def _nvd_response(cve_id: str, metrics: dict) -> MagicMock:
    """Build a minimal fake httpx.Response for a single-CVE NVD 2.0 reply."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "metrics": metrics,
                }
            }
        ]
    }
    resp.raise_for_status = MagicMock()
    return resp


def _empty_nvd_response(cve_id: str) -> MagicMock:
    """NVD response for a known CVE but with no metric entries."""
    return _nvd_response(cve_id, {})


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestFetchNvdCvssBatch:
    """Unit tests for _fetch_nvd_cvss_batch (NVD CVSS enrichment)."""

    def test_fetch_nvd_cvss_batch_success(self):
        """Parses cvssMetricV31 correctly and returns (score, severity)."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        metrics = {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        }
        mock_resp = _nvd_response("CVE-2021-44228", metrics)

        with patch("backend.core.cve_intel.httpx.get", return_value=mock_resp) as mock_get:
            result = _fetch_nvd_cvss_batch(["CVE-2021-44228"])

        assert result == {"CVE-2021-44228": (9.8, "critical")}
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["cveId"] == "CVE-2021-44228"

    def test_fetch_nvd_cvss_batch_fallback(self):
        """Falls back to cvssMetricV30 when cvssMetricV31 is absent."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        metrics = {
            "cvssMetricV30": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        }
        mock_resp = _nvd_response("CVE-2019-11043", metrics)

        with patch("backend.core.cve_intel.httpx.get", return_value=mock_resp):
            result = _fetch_nvd_cvss_batch(["CVE-2019-11043"])

        assert result == {"CVE-2019-11043": (7.5, "high")}

    def test_fetch_nvd_cvss_batch_v2_fallback_derives_severity(self):
        """Falls back to cvssMetricV2 and derives severity from score when absent."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        metrics = {
            "cvssMetricV2": [
                {
                    "cvssData": {
                        "baseScore": 6.8,
                        # baseSeverity intentionally absent (common in v2 responses)
                    }
                }
            ]
        }
        mock_resp = _nvd_response("CVE-2014-6271", metrics)

        with patch("backend.core.cve_intel.httpx.get", return_value=mock_resp):
            result = _fetch_nvd_cvss_batch(["CVE-2014-6271"])

        assert result == {"CVE-2014-6271": (6.8, "medium")}

    def test_fetch_nvd_cvss_batch_no_metrics(self):
        """Returns empty dict when NVD has no CVSS metrics for the CVE."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        mock_resp = _empty_nvd_response("CVE-2099-9999")

        with patch("backend.core.cve_intel.httpx.get", return_value=mock_resp):
            result = _fetch_nvd_cvss_batch(["CVE-2099-9999"])

        assert result == {}

    def test_fetch_nvd_cvss_batch_empty_input(self):
        """Returns empty dict immediately without any HTTP calls."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        with patch("backend.core.cve_intel.httpx.get") as mock_get:
            result = _fetch_nvd_cvss_batch([])

        assert result == {}
        mock_get.assert_not_called()

    def test_fetch_nvd_cvss_batch_http_error_skipped(self):
        """HTTP errors for one CVE are skipped; others still processed."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch
        import httpx as _httpx

        good_metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]
        }
        good_resp = _nvd_response("CVE-2020-0001", good_metrics)

        error_resp = MagicMock()
        error_resp.status_code = 404
        error_resp.raise_for_status.side_effect = _httpx.HTTPStatusError(
            "404", request=MagicMock(), response=error_resp
        )

        with patch(
            "backend.core.cve_intel.httpx.get",
            side_effect=[error_resp, good_resp],
        ):
            result = _fetch_nvd_cvss_batch(["CVE-1999-MISSING", "CVE-2020-0001"])

        assert "CVE-1999-MISSING" not in result
        assert result["CVE-2020-0001"] == (5.0, "medium")

    def test_fetch_nvd_cvss_batch_includes_api_key_header(self):
        """When nvd_api_key is set, the apiKey header is sent."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]
        }
        mock_resp = _nvd_response("CVE-2022-0001", metrics)

        with patch("backend.core.cve_intel.settings") as mock_settings, \
             patch("backend.core.cve_intel.httpx.get", return_value=mock_resp) as mock_get:
            mock_settings.nvd_api_key = "test-key-abc"
            mock_settings.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

            result = _fetch_nvd_cvss_batch(["CVE-2022-0001"])

        _, kwargs = mock_get.call_args
        assert kwargs["headers"].get("apiKey") == "test-key-abc"

    def test_fetch_nvd_cvss_batch_no_api_key_no_header(self):
        """When nvd_api_key is None, no apiKey header is sent."""
        from backend.core.cve_intel import _fetch_nvd_cvss_batch

        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM"}}]
        }
        mock_resp = _nvd_response("CVE-2022-0002", metrics)

        with patch("backend.core.cve_intel.settings") as mock_settings, \
             patch("backend.core.cve_intel.httpx.get", return_value=mock_resp) as mock_get:
            mock_settings.nvd_api_key = None
            mock_settings.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

            result = _fetch_nvd_cvss_batch(["CVE-2022-0002"])

        _, kwargs = mock_get.call_args
        assert "apiKey" not in kwargs["headers"]


class TestRunSyncEnrichesKevCvss:
    """Verifies that run_sync calls _fetch_nvd_cvss_batch for KEV CVEs lacking CVSS."""

    def _make_kev_json(self, cve_ids: list[str]) -> dict:
        return {
            "dateReleased": "2024-01-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": cve_id,
                    "dateAdded": "2024-01-01",
                    "knownRansomwareCampaignUse": "Unknown",
                    "vulnerabilityName": f"Test {cve_id}",
                    "shortDescription": "Test",
                    "notes": "",
                }
                for cve_id in cve_ids
            ],
        }

    def _make_epss_csv(self) -> bytes:
        import gzip
        content = "#model_version:v2023.03.01,score_date:2024-01-01T00:00:00Z\ncve,epss,percentile\n"
        return gzip.compress(content.encode())

    def test_run_sync_enriches_kev_cvss(self):
        """
        run_sync should call _fetch_nvd_cvss_batch with KEV CVE IDs that have
        null cvss_score in the DB after the initial upsert.
        """
        from backend.core import cve_intel

        kev_ids = ["CVE-2021-44228", "CVE-2021-26855"]

        kev_resp = MagicMock()
        kev_resp.raise_for_status = MagicMock()
        kev_resp.json.return_value = self._make_kev_json(kev_ids)

        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.content = self._make_epss_csv()

        # DB: snapshot_epss RPC, upsert, and the null-score query.
        mock_supabase = MagicMock()
        # snapshot_epss RPC
        mock_supabase.rpc.return_value.execute.return_value = MagicMock()
        # upsert chain
        mock_supabase.table.return_value.upsert.return_value.execute.return_value = MagicMock()
        # null-score query: both KEV CVEs are missing CVSS
        null_score_result = MagicMock()
        null_score_result.data = [{"cve_id": cid} for cid in kev_ids]
        (
            mock_supabase.table.return_value
            .select.return_value
            .in_.return_value
            .is_.return_value
            .execute.return_value
        ) = null_score_result

        with patch("backend.core.cve_intel.httpx.get", side_effect=[kev_resp, epss_resp]), \
             patch("backend.core.cve_intel.supabase", mock_supabase), \
             patch.object(cve_intel, "_fetch_nvd_cvss_batch", return_value={
                 "CVE-2021-44228": (10.0, "critical"),
                 "CVE-2021-26855": (9.1, "critical"),
             }) as mock_fetch:
            cve_intel.run_sync(include_epss=True)

        mock_fetch.assert_called_once()
        called_ids = set(mock_fetch.call_args[0][0])
        assert called_ids == set(kev_ids)

    def test_run_sync_skips_enrichment_when_all_scores_present(self):
        """
        run_sync should NOT call _fetch_nvd_cvss_batch when all KEV CVEs
        already have CVSS scores in the DB.
        """
        from backend.core import cve_intel

        kev_ids = ["CVE-2021-44228"]

        kev_resp = MagicMock()
        kev_resp.raise_for_status = MagicMock()
        kev_resp.json.return_value = self._make_kev_json(kev_ids)

        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.content = self._make_epss_csv()

        mock_supabase = MagicMock()
        mock_supabase.rpc.return_value.execute.return_value = MagicMock()
        mock_supabase.table.return_value.upsert.return_value.execute.return_value = MagicMock()
        # null-score query returns empty → no CVEs need enrichment
        null_score_result = MagicMock()
        null_score_result.data = []
        (
            mock_supabase.table.return_value
            .select.return_value
            .in_.return_value
            .is_.return_value
            .execute.return_value
        ) = null_score_result

        with patch("backend.core.cve_intel.httpx.get", side_effect=[kev_resp, epss_resp]), \
             patch("backend.core.cve_intel.supabase", mock_supabase), \
             patch.object(cve_intel, "_fetch_nvd_cvss_batch") as mock_fetch:
            cve_intel.run_sync(include_epss=True)

        mock_fetch.assert_not_called()
