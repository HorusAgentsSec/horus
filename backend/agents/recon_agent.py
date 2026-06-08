"""
ReconAgent — runs scanner subprocesses and populates raw_findings.
This is the ONLY agent that touches the network or filesystem directly.
No LLM calls.
"""

import logging
from backend.agents.base import BaseAgent
from backend.agents.state import ScanState
from backend.core.target_validation import validate_scan_target, TargetValidationError
from backend.scanners.nuclei_scanner import NucleiScanner
from backend.scanners.nmap_scanner import NmapScanner

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    agent_type = "recon"

    def run(self, state: ScanState) -> ScanState:
        asset = state.asset

        # Defense in depth: never launch a subprocess against an unvalidated target,
        # even if a bad host slipped past asset creation.
        try:
            validate_scan_target(asset.host, asset.is_internal)
        except TargetValidationError as e:
            msg = f"Refusing to scan unsafe target '{asset.host}': {e}"
            logger.error(msg)
            state.errors.append(msg)
            return state

        scanners = []

        # Always run nmap for port/service discovery
        scanners.append(NmapScanner())

        # Run nuclei for web/api targets
        if asset.type in ("web", "api", "domain"):
            scanners.append(NucleiScanner())

        for scanner in scanners:
            try:
                findings = scanner.scan(asset.host, asset.port)
                state.raw_findings.extend(findings)
                # Scanners that do version detection (nmap) expose detected services
                # for CPE->CVE correlation downstream.
                state.detected_services.extend(getattr(scanner, "detected_services", []))
                logger.info(
                    f"ReconAgent: {scanner.__class__.__name__} found "
                    f"{len(findings)} findings on {asset.host}"
                )
            except Exception as e:
                msg = f"Scanner {scanner.__class__.__name__} failed: {e}"
                logger.error(msg)
                state.errors.append(msg)

        return state
