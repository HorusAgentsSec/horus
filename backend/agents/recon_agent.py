"""
run_recon — runs scanner subprocesses and populates raw_findings.
This is the ONLY step that touches the network or filesystem directly.
No LLM calls.
"""

import logging
from backend.agents.state import ScanState
from backend.core.target_validation import validate_scan_target, TargetValidationError
from backend.scanners.nuclei_scanner import NucleiScanner
from backend.scanners.nmap_scanner import NmapScanner

logger = logging.getLogger(__name__)


def run_recon(state: ScanState) -> ScanState:
    asset = state.asset

    # Defense in depth: never launch a subprocess against an unvalidated target,
    # even if a bad host slipped past asset creation.
    try:
        # Use the validated/normalized host (URL -> host, :port stripped) for the scan,
        # not the raw asset.host, so the sanitized value actually reaches the subprocess.
        clean_host = validate_scan_target(asset.host, asset.is_internal)
    except TargetValidationError as e:
        msg = f"Refusing to scan unsafe target '{asset.host}': {e}"
        logger.error(msg)
        state.errors.append(msg)
        return state

    scanners = []
    scanners.append(NmapScanner())
    if asset.type in ("web", "api", "domain"):
        scanners.append(NucleiScanner())

    for scanner in scanners:
        try:
            findings = scanner.scan(clean_host, asset.port, scan_id=state.scan_id)
            state.raw_findings.extend(findings)
            state.detected_services.extend(getattr(scanner, "detected_services", []))
            logger.info(
                "run_recon: %s found %d findings on %s",
                scanner.__class__.__name__, len(findings), clean_host,
            )
        except Exception as e:
            msg = f"Scanner {scanner.__class__.__name__} failed: {e}"
            logger.error(msg)
            state.errors.append(msg)

    return state
