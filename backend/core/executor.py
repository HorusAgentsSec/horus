"""
Bounded worker pool for scan pipelines.

Replaces the previous fire-and-forget `threading.Thread` per scan, which was unbounded:
a burst of triggers could spawn arbitrarily many threads, exhaust resources, and hammer
the LLM provider. Here every scan — whether user-triggered or scheduled — is submitted to a
single shared ThreadPoolExecutor sized by `pipeline_max_concurrency`. Excess scans queue.

The pipeline import is deferred into the worker function to avoid importing the whole agent
stack (and constructing the LLM client) at module import time, and to sidestep import cycles.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from backend.core.config import settings
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(
    max_workers=settings.pipeline_max_concurrency,
    thread_name_prefix="scan-pipeline",
)


def submit_scan(scan_id: str, org_id: str, retries_left: int = 0) -> None:
    """Queues a scan pipeline on the bounded pool. Returns immediately. `retries_left` auto-retries
    the scan if it fails (used for scheduled scans so an unattended schedule self-heals)."""
    _executor.submit(_run_scan_safe, scan_id, org_id, retries_left)


def _run_scan_safe(scan_id: str, org_id: str, retries_left: int = 0) -> None:
    """Runs one pipeline and guarantees the scan is marked failed if it crashes. On failure with
    retries remaining, resets the scan to pending and requeues it."""
    from backend.agents.pipeline import run_pipeline_for_scan

    failed = False
    try:
        state = run_pipeline_for_scan(scan_id, org_id)
        # run_pipeline_for_scan marks the scan failed on agent errors; reflect that here so we can
        # decide on a retry. A canceled scan must never be retried.
        failed = bool(state and state.errors and not state.canceled)
    except Exception as e:
        failed = True
        logger.exception("Scan pipeline %s crashed", scan_id)
        try:
            supabase.table("scans").update(
                {"status": "failed", "error_message": str(e)}
            ).eq("id", scan_id).execute()
        except Exception:
            logger.exception("Could not mark scan %s as failed", scan_id)

    if failed and retries_left > 0:
        logger.info("Retrying failed scan %s (%d attempt(s) left)", scan_id, retries_left)
        try:
            # Reset to pending so run_pipeline_for_scan (which only starts from pending) re-runs it.
            supabase.table("scans").update(
                {"status": "pending", "error_message": None, "started_at": None, "completed_at": None}
            ).eq("id", scan_id).execute()
            submit_scan(scan_id, org_id, retries_left - 1)
        except Exception:
            logger.exception("Could not requeue scan %s for retry", scan_id)


def shutdown(wait: bool = False) -> None:
    """Stops accepting new scans; lets in-flight ones finish if wait=True."""
    _executor.shutdown(wait=wait)
