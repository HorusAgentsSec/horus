"""
ZAP scanner — wraps OWASP ZAP via its REST API (zap-cli or direct HTTP).
Requires ZAP running as a daemon: `zap.sh -daemon -port 8090`
"""

import logging
import os
import time
import httpx
from backend.agents.state import RawFinding
from backend.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

ZAP_BASE = "http://localhost:8090"
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")  # Set via env if ZAP is configured with an API key
ZAP_SCAN_TIMEOUT = 300  # seconds to wait for the active scan to finish before reading alerts

SEVERITY_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


class ZapScanner(BaseScanner):
    def scan(self, host: str, port: int | None = None) -> list[RawFinding]:
        target = f"http://{host}:{port}" if port else f"http://{host}"

        try:
            # Start spider
            httpx.get(
                f"{ZAP_BASE}/JSON/spider/action/scan/",
                params={"url": target, "apikey": ZAP_API_KEY},
                timeout=10,
            )
            # Start active scan
            ascan_resp = httpx.get(
                f"{ZAP_BASE}/JSON/ascan/action/scan/",
                params={"url": target, "apikey": ZAP_API_KEY},
                timeout=10,
            )
            scan_id = ascan_resp.json().get("scan")

            # spider/ascan are async: poll until the active scan reports 100% (or we hit
            # the global timeout) before reading alerts, or we get empty/partial results.
            deadline = time.monotonic() + ZAP_SCAN_TIMEOUT
            while scan_id is not None and time.monotonic() < deadline:
                status_resp = httpx.get(
                    f"{ZAP_BASE}/JSON/ascan/view/status/",
                    params={"scanId": scan_id, "apikey": ZAP_API_KEY},
                    timeout=10,
                )
                if status_resp.json().get("status") == "100":
                    break
                time.sleep(2)

            # Retrieve alerts
            resp = httpx.get(
                f"{ZAP_BASE}/JSON/alert/view/alerts/",
                params={"baseurl": target, "apikey": ZAP_API_KEY},
                timeout=30,
            )
            alerts = resp.json().get("alerts", [])
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.warning(f"ZAP not reachable at {ZAP_BASE}: {e}")
            return []

        findings = []
        for alert in alerts:
            findings.append(
                RawFinding(
                    tool="zap",
                    template_id=alert.get("pluginId"),
                    name=alert.get("name", ""),
                    host=host,
                    severity=SEVERITY_MAP.get(alert.get("risk", "Low"), "low"),
                    raw=alert,
                )
            )

        logger.info(f"ZapScanner: {len(findings)} alerts on {target}")
        return findings
