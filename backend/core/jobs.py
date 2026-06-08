"""
Job history — the operations log for all background work.

Every scheduled scan, discovery run, CVE sync, Watchtower pass, posture snapshot and board report
records a row in `jobs`: when it ran, how long it took, whether it succeeded, and a small result
summary. The UI reads this back as a history so failures are visible — the observability that makes
"configure once and trust it" actually trustworthy.

Use the `job_run` context manager around a unit of work. It's best-effort: a logging failure (or a
missing table) must never break the job itself, so every DB write is guarded.

    with job_run("cve_sync") as detail:
        detail["rows"] = run_sync()        # whatever you put in `detail` is persisted

On success the row is marked completed; on exception it's marked failed (with the error) and the
exception re-raised so the caller's own handling still runs.
"""

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Known job types (kept in sync with the scheduler entry points + manual triggers).
SCAN_SCHEDULE = "scan_schedule"
DISCOVERY = "discovery"
CVE_SYNC = "cve_sync"
WATCHTOWER = "watchtower"
POSTURE_SNAPSHOT = "posture_snapshot"
POSTURE_REPORT = "posture_report"
COMMUNITY_REFRESH = "community_refresh"


def _insert_running(job_type: str, org_id, ref_id, trigger: str) -> str | None:
    from backend.core.supabase_client import supabase

    try:
        res = (
            supabase.table("jobs")
            .insert(
                {
                    "job_type": job_type,
                    "org_id": org_id,
                    "ref_id": ref_id,
                    "trigger": trigger,
                    "status": "running",
                }
            )
            .execute()
        )
        return res.data[0]["id"] if res.data else None
    except Exception:
        logger.debug("jobs: failed to record start of %s", job_type, exc_info=True)
        return None


def _finish(job_id: str, status: str, detail: dict, started: float, error: str | None) -> None:
    from backend.core.supabase_client import supabase

    try:
        supabase.table("jobs").update(
            {
                "status": status,
                "detail": detail or {},
                "error": error,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
        ).eq("id", job_id).execute()
    except Exception:
        logger.debug("jobs: failed to record finish of %s", job_id, exc_info=True)


@contextmanager
def job_run(job_type: str, org_id: str | None = None, ref_id: str | None = None, trigger: str = "cron"):
    """Record a background job execution. Yields a mutable `detail` dict whose contents are
    persisted as the job's result summary. Best-effort logging; the wrapped work is never blocked
    by a logging failure."""
    started = time.monotonic()
    job_id = _insert_running(job_type, org_id, ref_id, trigger)
    detail: dict = {}
    try:
        yield detail
    except Exception as e:
        if job_id:
            _finish(job_id, "failed", detail, started, error=str(e)[:1000])
        raise
    else:
        if job_id:
            _finish(job_id, "completed", detail, started, error=None)
