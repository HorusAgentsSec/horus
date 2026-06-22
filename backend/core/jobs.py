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
        # detail.job_id exposes the DB row id for cooperative cancellation checks

On success the row is marked completed; on exception it's marked failed (with the error) and the
exception re-raised so the caller's own handling still runs. If the job was externally canceled
via cancel.request(job_id), the row is marked 'canceled' instead.
"""

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def purge_old_jobs(retention_days: int = 90) -> int:
    """Delete finished job rows older than retention_days so the table does not grow
    unbounded (iris_triage et al. insert a row every few minutes). Best-effort; the
    .lt filter both bounds the delete and excludes still-running rows (finished_at NULL)."""
    from backend.core.supabase_client import supabase

    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    try:
        res = supabase.table("jobs").delete().lt("finished_at", cutoff).execute()
        return len(res.data or [])
    except Exception:
        logger.debug("jobs: purge failed", exc_info=True)
        return 0

# Known job types (kept in sync with the scheduler entry points + manual triggers).
SCAN_SCHEDULE = "scan_schedule"
DISCOVERY = "discovery"
CVE_SYNC = "cve_sync"
WATCHTOWER = "watchtower"
POSTURE_SNAPSHOT = "posture_snapshot"
POSTURE_REPORT = "posture_report"
COMMUNITY_REFRESH = "community_refresh"
ADVERSARIAL = "adversarial"
CLOUD_AUDIT = "cloud_audit"


class _JobDetail(dict):
    """A mutable dict (backwards-compatible) that also carries the DB row id
    so workers can check cooperative cancellation via cancel.is_canceled(detail.job_id)."""
    def __init__(self):
        super().__init__()
        self.job_id: str | None = None


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
        # .neq("status", "canceled") prevents overwriting an externally-set canceled status.
        supabase.table("jobs").update(
            {
                "status": status,
                "detail": dict(detail) if detail else {},
                "error": error,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
        ).eq("id", job_id).neq("status", "canceled").execute()
    except Exception:
        logger.debug("jobs: failed to record finish of %s", job_id, exc_info=True)


def _db_status_is_canceled(job_id: str) -> bool:
    """Re-read the job row to catch a cancellation set by another process. The in-memory
    cancel flag isn't shared across workers, so a job canceled via the API in the web
    process wouldn't be seen by a worker process relying on cancel.is_canceled alone."""
    from backend.core.supabase_client import supabase

    try:
        res = supabase.table("jobs").select("status").eq("id", job_id).single().execute()
        return bool(res.data and res.data.get("status") == "canceled")
    except Exception:
        return False


@contextmanager
def job_run(job_type: str, org_id: str | None = None, ref_id: str | None = None, trigger: str = "cron"):
    """Record a background job execution. Yields a `_JobDetail` (dict subclass) whose contents
    are persisted as the job's result summary. `detail.job_id` is the DB row id — pass it to
    workers so they can check cancel.is_canceled(detail.job_id) at safe checkpoints."""
    from backend.core import cancel

    started = time.monotonic()
    job_id = _insert_running(job_type, org_id, ref_id, trigger)
    detail = _JobDetail()
    detail.job_id = job_id
    try:
        yield detail
    except Exception as e:
        if job_id:
            canceled = cancel.is_canceled(job_id) or _db_status_is_canceled(job_id)
            status = "canceled" if canceled else "failed"
            _finish(job_id, status, detail, started, error=None if canceled else str(e)[:1000])
        cancel.clear(job_id)
        raise
    else:
        if job_id:
            canceled = cancel.is_canceled(job_id) or _db_status_is_canceled(job_id)
            status = "canceled" if canceled else "completed"
            _finish(job_id, status, detail, started, error=None)
        cancel.clear(job_id)
