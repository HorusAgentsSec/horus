from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from backend.core.config import settings
from backend.core.supabase_client import supabase
from backend.core import jobs, maintenance
from datetime import datetime
from zoneinfo import ZoneInfo
import logging

logger = logging.getLogger(__name__)
# coalesce: si se pierden varios disparos de un cron (el job anterior aun corria, o
# downtime), ejecutar solo uno al volver en vez de descartarlos en silencio.
# misfire_grace_time: ventana para recuperar un disparo perdido (1h) en lugar del
# default de 1s, que con scans largos saltaba ticks sin dejar rastro.
scheduler = BackgroundScheduler(
    job_defaults={"coalesce": True, "misfire_grace_time": 3600}
)


def _blackout_now() -> datetime:
    """Current time in the timezone the blackout windows are expressed in. Jobs record UTC, so
    evaluating windows against a naive datetime.now() would be off by the server's UTC offset
    (the deploy runs UTC). Use the configured tz, or the server-local tz when unset."""
    tz = settings.scan_blackout_timezone.strip()
    if tz:
        try:
            return datetime.now(ZoneInfo(tz))
        except Exception:
            logger.warning("Invalid scan_blackout_timezone %r, falling back to local time", tz)
    return datetime.now().astimezone()  # aware, server-local


def _in_blackout_now() -> bool:
    """Whether right now falls inside a configured maintenance (blackout) window."""
    return maintenance.in_blackout(
        _blackout_now(), maintenance.parse_windows(settings.scan_blackout_windows)
    )


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
            if trigger == "cron" and _in_blackout_now():
                d["skipped"] = "blackout_window"
                return
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
            if trigger == "cron" and _in_blackout_now():
                d["skipped"] = "blackout_window"
                return
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


def _run_adversarial():
    from backend.core.adversarial import run_adversarial_cycle
    try:
        with jobs.job_run(jobs.ADVERSARIAL) as d:
            d.update(run_adversarial_cycle() or {})
    except Exception as e:
        logger.error(f"Adversarial cycle failed: {e}")


def _register_adversarial():
    """Daily Red→Blue adversarial cycle across all orgs (runs before CVE sync chain)."""
    if not settings.adversarial_enabled:
        return
    try:
        scheduler.add_job(
            _run_adversarial,
            CronTrigger.from_crontab(settings.adversarial_cron),
            id="adversarial",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register adversarial job: {e}")


def _run_ransomware_check_all_orgs():
    """Daily ransomware.live victim check across all orgs."""
    from backend.core.watchtower import run_ransomware_check
    try:
        with jobs.job_run("ransomware_check") as d:
            orgs = supabase.table("organizations").select("id").execute().data or []
            total_checked = 0
            total_matches = 0
            for org in orgs:
                result = run_ransomware_check(org["id"])
                total_checked += result.get("checked", 0)
                total_matches += result.get("matches", 0)
            d["checked"] = total_checked
            d["matches"] = total_matches
            d["orgs"] = len(orgs)
    except Exception as e:
        logger.error(f"Ransomware check failed: {e}")


def _register_ransomware_check():
    """Daily ransomware.live victim database check across all orgs (runs after watchtower)."""
    if not settings.ransomware_check_enabled:
        return
    try:
        scheduler.add_job(
            _run_ransomware_check_all_orgs,
            CronTrigger.from_crontab(settings.ransomware_check_cron),
            id="ransomware_check",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register ransomware check job: {e}")


def _run_ioc_check_all_orgs():
    """Daily abuse.ch IOC (ThreatFox + URLhaus) check across all orgs."""
    from backend.core.watchtower import run_ioc_check
    try:
        with jobs.job_run("ioc_check") as d:
            orgs = supabase.table("organizations").select("id").execute().data or []
            total_checked = 0
            total_threatfox = 0
            total_urlhaus = 0
            for org in orgs:
                result = run_ioc_check(org["id"])
                total_checked += result.get("checked", 0)
                total_threatfox += result.get("threatfox_matches", 0)
                total_urlhaus += result.get("urlhaus_matches", 0)
            d["checked"] = total_checked
            d["threatfox_matches"] = total_threatfox
            d["urlhaus_matches"] = total_urlhaus
            d["orgs"] = len(orgs)
    except Exception as e:
        logger.error(f"IOC check failed: {e}")


def _register_ioc_check():
    """Daily abuse.ch IOC database check (ThreatFox + URLhaus) across all orgs (runs after ransomware check)."""
    if not settings.ioc_check_enabled:
        return
    try:
        scheduler.add_job(
            _run_ioc_check_all_orgs,
            CronTrigger.from_crontab(settings.ioc_check_cron),
            id="ioc_check",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register IOC check job: {e}")


# ── per-org adversarial schedules ─────────────────────────────────────────────

def _run_scheduled_adversarial(schedule_id: str, trigger: str = "cron"):
    from backend.core.adversarial import run_adversarial_cycle

    org_id = None
    try:
        row = supabase.table("adversarial_schedules").select("org_id").eq("id", schedule_id).single().execute()
        org_id = (row.data or {}).get("org_id")
    except Exception:
        pass
    try:
        with jobs.job_run("adversarial_schedule", org_id=org_id, ref_id=schedule_id, trigger=trigger) as d:
            d.update(run_adversarial_cycle(org_id=org_id) or {})
    except Exception as e:
        logger.error(f"Scheduled adversarial {schedule_id} failed: {e}")


def schedule_adversarial_job(s: dict) -> None:
    job_id = f"adversarial:{s['id']}"
    if not s.get("enabled", True):
        unschedule_job(job_id)
        return
    try:
        scheduler.add_job(
            _run_scheduled_adversarial,
            CronTrigger.from_crontab(s["cron_expression"]),
            args=[s["id"]],
            id=job_id,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not schedule adversarial {s['id']}: {e}")


def load_adversarial_schedules():
    rows = supabase.table("adversarial_schedules").select("*").eq("enabled", True).execute()
    for s in rows.data:
        schedule_adversarial_job(s)


# ── per-org phishing schedules ────────────────────────────────────────────────

def _run_scheduled_phishing(schedule_id: str, trigger: str = "cron"):
    import secrets as _secrets
    from datetime import datetime, timezone
    from backend.api.phishing import _launch_campaign

    s = supabase.table("phishing_schedules").select("*").eq("id", schedule_id).single().execute().data
    if not s:
        logger.error(f"Phishing schedule {schedule_id} not found")
        return

    org_id      = s["org_id"]
    contact_ids = s.get("contact_ids") or []
    asset_ids   = s.get("context_asset_ids") or []
    objective   = s.get("objective", "click")

    if not contact_ids:
        logger.warning(f"Phishing schedule {schedule_id} has no contacts, skipping")
        return

    contacts = (
        supabase.table("phishing_contacts")
        .select("id, name, email")
        .in_("id", contact_ids)
        .eq("org_id", org_id)
        .execute()
        .data or []
    )
    if not contacts:
        logger.warning(f"Phishing schedule {schedule_id}: contacts not found, skipping")
        return

    # job_run wraps the launch so a crash/cancel marks the row failed/canceled with a
    # finished_at + duration, instead of leaving it stuck at 'running' forever.
    try:
        with jobs.job_run("phishing_schedule", org_id=org_id, ref_id=schedule_id, trigger=trigger) as d:
            camp = supabase.table("phishing_campaigns").insert({
                "org_id":            org_id,
                "name":              f"{s['name']} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})",
                "objective":         objective,
                "context_asset_ids": asset_ids,
                "status":            "running",
                "launched_at":       datetime.now(timezone.utc).isoformat(),
            }).execute().data[0]
            campaign_id = camp["id"]

            target_rows = [
                {
                    "campaign_id":    campaign_id,
                    "org_id":         org_id,
                    "employee_name":  c["name"],
                    "employee_email": c["email"],
                    "tracking_token": _secrets.token_hex(24),
                }
                for c in contacts
            ]
            supabase.table("phishing_targets").insert(target_rows).execute()

            d["campaign"] = camp["name"]
            d["targets"] = len(target_rows)
            _launch_campaign(campaign_id, org_id, d.job_id)
    except Exception as e:
        logger.error(f"Scheduled phishing {schedule_id} failed: {e}")


def schedule_phishing_job(s: dict) -> None:
    job_id = f"phishing:{s['id']}"
    if not s.get("enabled", True):
        unschedule_job(job_id)
        return
    try:
        scheduler.add_job(
            _run_scheduled_phishing,
            CronTrigger.from_crontab(s["cron_expression"]),
            args=[s["id"]],
            id=job_id,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not schedule phishing {s['id']}: {e}")


def load_phishing_schedules():
    rows = supabase.table("phishing_schedules").select("*").eq("enabled", True).execute()
    for s in rows.data:
        schedule_phishing_job(s)


def _run_iris_triage():
    from backend.core.iris_triage import run_iris_triage_all_orgs, detect_offline_agents
    try:
        with jobs.job_run("iris_triage") as d:
            # Offline detection runs every poll regardless of per-org triage intervals,
            # so a dark host is flagged within one check window, not one triage window.
            d.update(detect_offline_agents() or {})
            d.update(run_iris_triage_all_orgs(settings.iris_triage_check_minutes) or {})
    except Exception as e:
        logger.error(f"Iris triage failed: {e}")


def _register_iris_triage():
    if not settings.iris_triage_enabled:
        return
    try:
        scheduler.add_job(
            _run_iris_triage,
            "interval",
            minutes=settings.iris_triage_check_minutes,
            id="iris_triage",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register Iris triage job: {e}")


def _run_jobs_purge():
    retention = getattr(settings, "jobs_retention_days", 90)
    try:
        with jobs.job_run("jobs_purge") as d:
            d["deleted"] = jobs.purge_old_jobs(retention)
    except Exception as e:
        logger.error(f"Jobs purge failed: {e}")


def _register_jobs_purge():
    try:
        scheduler.add_job(
            _run_jobs_purge,
            CronTrigger.from_crontab("30 3 * * *"),  # daily at 03:30
            id="jobs_purge",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning(f"Could not register jobs purge: {e}")


def start():
    load_schedules()
    load_discovery_sources()
    load_adversarial_schedules()
    load_phishing_schedules()
    _register_iris_triage()
    _register_cve_sync()
    _register_watchtower()
    _register_ransomware_check()
    _register_ioc_check()
    _register_posture_snapshot()
    _register_posture_report()
    _register_community_refresh()
    _register_adversarial()
    _register_jobs_purge()
    scheduler.start()


def stop():
    scheduler.shutdown()
