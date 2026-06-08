from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from backend.core.config import settings
from backend.core.supabase_client import supabase
from backend.core import jobs
import logging

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler()


def _run_scheduled_scan(schedule_id: str, trigger: str = "cron"):
    from backend.agents.pipeline import run_pipeline_for_schedule

    # Look up the owning org so the job row is org-scoped (not visible to other tenants).
    org_id = None
    try:
        row = supabase.table("scan_schedules").select("org_id").eq("id", schedule_id).single().execute()
        org_id = (row.data or {}).get("org_id")
    except Exception:
        pass
    try:
        with jobs.job_run(jobs.SCAN_SCHEDULE, org_id=org_id, ref_id=schedule_id, trigger=trigger) as d:
            submitted = run_pipeline_for_schedule(schedule_id)
            d["scans_submitted"] = submitted or 0
    except Exception as e:
        logger.error(f"Scheduled scan {schedule_id} failed: {e}")


def _run_cve_sync():
    from backend.core.cve_intel import run_sync
    try:
        with jobs.job_run(jobs.CVE_SYNC) as d:
            d["rows"] = run_sync()
    except Exception as e:
        logger.error(f"CVE intel sync failed: {e}")


def _register_cve_sync():
    """Daily refresh of the global CVE intelligence table (KEV + EPSS)."""
    if not settings.cve_sync_enabled:
        return
    try:
        scheduler.add_job(
            _run_cve_sync,
            CronTrigger.from_crontab(settings.cve_sync_cron),
            id="cve_intel_sync",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register CVE sync job: {e}")


def _run_watchtower(trigger: str = "cron"):
    from backend.core.watchtower import run_watchtower
    try:
        with jobs.job_run(jobs.WATCHTOWER, trigger=trigger) as d:
            d.update(run_watchtower() or {})
    except Exception as e:
        logger.error(f"Watchtower run failed: {e}")


def _register_watchtower():
    """Daily continuous-exposure check: re-correlate the asset inventory against newly
    known-exploited CVEs (runs shortly after the KEV/EPSS sync)."""
    if not settings.watchtower_enabled:
        return
    try:
        scheduler.add_job(
            _run_watchtower,
            CronTrigger.from_crontab(settings.watchtower_cron),
            id="watchtower",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register watchtower job: {e}")


def _run_posture_snapshot():
    from backend.core.posture import snapshot_all_orgs
    try:
        with jobs.job_run(jobs.POSTURE_SNAPSHOT) as d:
            d["orgs"] = snapshot_all_orgs()
    except Exception as e:
        logger.error(f"Posture snapshot run failed: {e}")


def _register_posture_snapshot():
    """Daily posture snapshot for every org, so the executive timeline has a point each day
    even when no scan ran (captures aging findings + new Watchtower alerts)."""
    if not settings.posture_snapshot_enabled:
        return
    try:
        scheduler.add_job(
            _run_posture_snapshot,
            CronTrigger.from_crontab(settings.posture_snapshot_cron),
            id="posture_snapshot",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register posture snapshot job: {e}")


def _run_posture_report():
    from backend.core.notify import send_all_posture_reports
    try:
        with jobs.job_run(jobs.POSTURE_REPORT) as d:
            d["sent"] = send_all_posture_reports(settings.posture_report_days)
    except Exception as e:
        logger.error(f"Posture report run failed: {e}")


def _run_community_refresh():
    from backend.core.verdict_memory import refresh_community
    try:
        with jobs.job_run(jobs.COMMUNITY_REFRESH):
            refresh_community()
    except Exception as e:
        logger.error(f"Community verdicts refresh failed: {e}")


def _register_community_refresh():
    """Daily recompute of the anonymized cross-org verdict aggregate (the false-positive flywheel)."""
    if not settings.community_verdicts_enabled:
        return
    try:
        scheduler.add_job(
            _run_community_refresh,
            CronTrigger.from_crontab(settings.community_verdicts_cron),
            id="community_refresh",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register community refresh job: {e}")


def _register_posture_report():
    """Monthly board report: email the posture PDF to every org's opted-in email integration."""
    if not settings.posture_report_enabled:
        return
    try:
        scheduler.add_job(
            _run_posture_report,
            CronTrigger.from_crontab(settings.posture_report_cron),
            id="posture_report",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register posture report job: {e}")


def schedule_job(s: dict) -> None:
    """
    Register (or replace) the APScheduler job for one schedule — or remove it if the
    schedule is disabled. Call this whenever a schedule is created/updated/deleted via
    the API so changes take effect live, without a server restart.
    """
    sid = s["id"]
    if not s.get("enabled", True):
        unschedule_job(sid)
        return
    try:
        scheduler.add_job(
            _run_scheduled_scan,
            CronTrigger.from_crontab(s["cron_expression"]),
            args=[sid],
            id=sid,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not schedule {sid}: {e}")


def unschedule_job(schedule_id: str) -> None:
    """Remove a schedule's job if present (no-op if it isn't registered)."""
    try:
        scheduler.remove_job(schedule_id)
    except Exception:
        pass  # job may not exist (disabled, never registered, or already removed)


def next_run_for(job_id: str) -> str | None:
    """ISO timestamp of a registered job's next fire time, or None if not scheduled."""
    try:
        job = scheduler.get_job(job_id)
        if job and job.next_run_time:
            return job.next_run_time.isoformat()
    except Exception:
        pass
    return None


def load_schedules():
    """Load all active schedules from DB and register them with APScheduler."""
    schedules = supabase.table("scan_schedules").select("*").eq("enabled", True).execute()
    for s in schedules.data:
        schedule_job(s)


# ── Asset discovery schedules ────────────────────────────────────────────────

def _run_discovery(source_id: str, org_id: str, trigger: str = "cron"):
    from backend.core.discovery import run_discovery
    try:
        with jobs.job_run(jobs.DISCOVERY, org_id=org_id, ref_id=source_id, trigger=trigger) as d:
            result = run_discovery(source_id, org_id)
            if isinstance(result, dict):
                d.update(result)
    except Exception as e:
        logger.error(f"Discovery {source_id} failed: {e}")


def discovery_job(source: dict) -> None:
    """Register/replace (or remove) the cron job for a discovery source. Job ids are
    namespaced 'discovery:<id>' so they never collide with scan schedule ids."""
    job_id = f"discovery:{source['id']}"
    if not source.get("enabled", True) or not source.get("cron_expression"):
        unschedule_job(job_id)  # manual-only or disabled → no cron job
        return
    try:
        scheduler.add_job(
            _run_discovery,
            CronTrigger.from_crontab(source["cron_expression"]),
            args=[source["id"], source["org_id"]],
            id=job_id,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not schedule discovery {source['id']}: {e}")


def unschedule_discovery(source_id: str) -> None:
    unschedule_job(f"discovery:{source_id}")


def load_discovery_sources():
    """Register all enabled, scheduled discovery sources at startup."""
    rows = supabase.table("discovery_sources").select("*").eq("enabled", True).execute()
    for s in rows.data:
        discovery_job(s)


def start():
    load_schedules()
    load_discovery_sources()
    _register_cve_sync()
    _register_watchtower()
    _register_posture_snapshot()
    _register_posture_report()
    _register_community_refresh()
    scheduler.start()


def stop():
    scheduler.shutdown()
