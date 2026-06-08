import logging
import os
import subprocess
import xml.etree.ElementTree as ET
import tempfile
from pathlib import Path

from backend.agents.state import RawFinding
from backend.core.process_registry import register_process, unregister_process
from backend.scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Ports commonly associated with vulnerabilities
DEFAULT_PORT_ARGS = "-p 21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017"

# nmap NSE scripts that report context/discovery info, not vulnerabilities. We skip
# these so the Findings view isn't polluted with non-issues (page titles, banners,
# headers, certs). Service/version data still flows via -sV detected_services, which
# is what drives CPE->CVE correlation.
INFORMATIONAL_SCRIPTS = {
    "http-title",
    "http-server-header",
    "http-headers",
    "http-methods",
    "http-favicon",
    "http-robots.txt",
    "http-generator",
    "http-date",
    "http-comments-displayer",
    "ssl-cert",
    "ssl-date",
    "tls-alpn",
    "tls-nextprotoneg",
    "banner",
    "fingerprint-strings",
}


class NmapScanner(BaseScanner):
    def scan(
        self,
        host: str,
        port: int | None = None,
        *,
        scan_id: str | None = None,
    ) -> list[RawFinding]:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            out_path = tmp.name

        port_args = ["-p", str(port)] if port else DEFAULT_PORT_ARGS.split()
        cmd = [
            "nmap",
            *port_args,
            "-sV",          # version detection
            "--script", "vuln,default",
            "-oX", out_path,
            "--host-timeout", "5m",
            host,
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            if scan_id:
                register_process(scan_id, process)
            process.communicate(timeout=360)
        except subprocess.TimeoutExpired:
            if scan_id:
                unregister_process(scan_id, process)
            try:
                os.killpg(process.pid, subprocess.signal.SIGKILL)
            except Exception:
                pass
            logger.warning(f"NmapScanner timed out on {host}")
            return []
        except FileNotFoundError:
            logger.error("nmap binary not found — skipping Nmap scan")
            return []
        finally:
            if scan_id and "process" in locals():
                unregister_process(scan_id, process)

        findings = self._parse_xml(out_path, host)
        Path(out_path).unlink(missing_ok=True)
        logger.info(f"NmapScanner: {len(findings)} findings on {host}")
        return findings

    def _parse_xml(self, path: str, host: str) -> list[RawFinding]:
        findings = []
        # Detected services for CPE->CVE correlation, regardless of script output.
        self.detected_services: list[dict] = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError):
            return findings

        for host_el in root.findall("host"):
            for port_el in host_el.findall(".//port"):
                port_id = port_el.get("portid", "")
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                # Record the detected software so the pipeline can correlate it to CVEs,
                # even when no vuln script fired on this port.
                if product and version:
                    self.detected_services.append(
                        {"product": product, "version": version, "port": port_id, "service": service_name}
                    )

                # Collect any script output (vuln scripts)
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    output = script_el.get("output", "")
                    if not output:
                        continue
                    # Skip purely informational scripts — they are not vulnerabilities.
                    if script_id in INFORMATIONAL_SCRIPTS:
                        continue

                    severity = _infer_severity(script_id, output)
                    findings.append(
                        RawFinding(
                            tool="nmap",
                            template_id=script_id,
                            name=f"{script_id} on {service_name}/{port_id}",
                            host=host,
                            severity=severity,
                            raw={
                                "port": port_id,
                                "service": service_name,
                                "product": product,
                                "version": version,
                                "script_id": script_id,
                                "output": output,
                            },
                        )
                    )

        return findings


def _infer_severity(script_id: str, output: str) -> str:
    output_lower = output.lower()
    if any(k in output_lower for k in ("exploit", "rce", "critical", "cvss: 9", "cvss: 10")):
        return "critical"
    if any(k in output_lower for k in ("vulnerable", "high", "cvss: 7", "cvss: 8")):
        return "high"
    if any(k in output_lower for k in ("medium", "cvss: 4", "cvss: 5", "cvss: 6")):
        return "medium"
    return "low"
