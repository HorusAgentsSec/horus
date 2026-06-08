import hashlib
import logging
from datetime import datetime, timezone

from backend.agents.state import ScanState, AssetInfo
from backend.agents.analyst_team import classify_domain
from backend.agents.recon_agent import ReconAgent
from backend.agents.analyst_agent import AnalystAgent
from backend.agents.correlation_agent import CorrelationAgent
from backend.agents.threat_intel_agent import ThreatIntelAgent
from backend.agents.validation_agent import ValidationAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.risk_manager_agent import RiskManagerAgent
from backend.agents.reporter_agent import ReporterAgent
from backend.core.executor import submit_scan
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

# Recon → Analyst → Correlation → ThreatIntel → Validation → Remediation → RiskManager → Reporter.
# Validation (the red/blue debate) sits after enrichment (so it can use KEV/EPSS exploitability to
# gate) and before Remediation (so we don't draft fixes for findings judged false positive).
AGENT_SEQUENCE = [
    ReconAgent,
    AnalystAgent,
    CorrelationAgent,
    ThreatIntelAgent,
    ValidationAgent,
    RemediationAgent,
    RiskManagerAgent,
    ReporterAgent,
]


def run_pipeline(state: ScanState) -> ScanState:
    """
    Sequential agent pipeline. Each agent mutates and returns state.
    Errors in one agent are logged and the pipeline continues.
    """
    for AgentClass in AGENT_SEQUENCE:
        if _scan_is_canceled(state.scan_id):
            state.canceled = True
            logger.info("Scan %s canceled before %s", state.scan_id, AgentClass.agent_type)
            return state

        agent = AgentClass()
        # Seed the per-run redactor so any LLM call this agent makes is pseudonymized.
        from backend.core.config import settings
        if settings.redaction_enabled:
            from backend.core.redaction import build_redactor

            agent.redactor = build_redactor(state)
        run_id = None
        try:
            run_id = _log_agent_start(state, agent.agent_type)
            state = agent.run(state)
            if _scan_is_canceled(state.scan_id):
                state.canceled = True
                logger.info("Scan %s canceled after %s", state.scan_id, agent.agent_type)
                return state
            if run_id is not None:
                _log_agent_complete(
                    run_id,
                    success=True,
                    tokens_used=agent.tokens_used,
                    model_used=agent.model_used,
                    detail=_agent_detail(agent.agent_type, state),
                )
        except Exception as e:
            msg = f"{agent.agent_type}: {e}"
            state.errors.append(msg)
            logger.error(f"Pipeline error — {msg}")
            if run_id is not None:
                _log_agent_complete(
                    run_id,
                    success=False,
                    error=str(e),
                    tokens_used=agent.tokens_used,
                    model_used=agent.model_used,
                )

    if not state.canceled:
        _persist_results(state)
    return state


def run_pipeline_for_scan(scan_id: str, org_id: str) -> ScanState:
    """Entry point called from the API trigger endpoint."""
    scan = supabase.table("scans").select("*, assets(*)").eq("id", scan_id).single().execute()
    if _scan_row_is_canceled(scan.data):
        logger.info("Scan %s was canceled before the worker started", scan_id)
        return None

    asset_row = scan.data["assets"]
    policies = (
        supabase.table("permission_policies")
        .select("rules")
        .eq("org_id", org_id)
        .eq("is_active", True)
        .execute()
    )
    permission_rules = []
    for p in policies.data:
        permission_rules.extend(p["rules"])

    state = ScanState(
        scan_id=scan_id,
        org_id=org_id,
        asset=AssetInfo(
            id=asset_row["id"],
            name=asset_row["name"],
            host=asset_row["host"],
            port=asset_row.get("port"),
            type=asset_row["type"],
            is_internal=asset_row["is_internal"],
            tags=asset_row.get("tags", []),
        ),
        permission_rules=permission_rules,
    )

    started = supabase.table("scans").update(
        {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", scan_id).eq("status", "pending").execute()
    if not started.data:
        logger.info("Scan %s did not transition from pending to running", scan_id)
        return state

    state = run_pipeline(state)

    if state.canceled or _scan_is_canceled(scan_id):
        _mark_scan_canceled(scan_id)
    else:
        supabase.table("scans").update(
            {
                "status": "completed" if not state.errors else "failed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": "; ".join(state.errors) if state.errors else None,
            }
        ).eq("id", scan_id).execute()
        # Push results to Slack/email integrations. Best-effort: never fails the scan.
        try:
            from backend.core.notify import notify_scan_complete
            notify_scan_complete(scan_id, org_id)
        except Exception:
            logger.exception("notify_scan_complete failed for scan %s", scan_id)
        # Capture a posture snapshot so the executive timeline reacts immediately to this
        # scan's findings (the daily cron also covers days with no scan). Best-effort.
        try:
            from backend.core.posture import snapshot_posture
            snapshot_posture(org_id)
        except Exception:
            logger.exception("posture snapshot failed for scan %s", scan_id)

    return state


def run_pipeline_for_schedule(schedule_id: str) -> int:
    """Entry point called from APScheduler. Returns the number of scans submitted."""
    schedule = (
        supabase.table("scan_schedules").select("*").eq("id", schedule_id).single().execute()
    )
    s = schedule.data
    submitted = 0
    for asset_id in s["asset_ids"]:
        asset = supabase.table("assets").select("org_id").eq("id", asset_id).single().execute()
        scan = (
            supabase.table("scans")
            .insert(
                {
                    "org_id": asset.data["org_id"],
                    "asset_id": asset_id,
                    "schedule_id": schedule_id,
                    "status": "pending",
                    "tools_used": s["tools"],
                    "triggered_by": "schedule",
                }
            )
            .execute()
        )
        # Route through the bounded pool so scheduled scans respect the same concurrency limit as
        # user-triggered ones. Scheduled scans auto-retry on failure so an unattended schedule
        # self-heals through transient errors.
        from backend.core.config import settings

        submit_scan(scan.data[0]["id"], asset.data["org_id"], settings.scan_max_retries)
        submitted += 1
    return submitted


def _log_agent_start(state: ScanState, agent_type: str) -> str:
    res = supabase.table("agent_runs").insert(
        {
            "org_id": state.org_id,
            "scan_id": state.scan_id,
            "agent_type": agent_type,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
    ).execute()
    return res.data[0]["id"]


def _log_agent_complete(
    run_id: str,
    success: bool,
    error: str = None,
    tokens_used: int = 0,
    model_used: str = None,
    detail: dict = None,
):
    supabase.table("agent_runs").update(
        {
            "status": "completed" if success else "failed",
            "error_message": error,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "tokens_used": tokens_used,
            "model_used": model_used,
            "output_state": detail or {},
        }
    ).eq("id", run_id).execute()


def _agent_detail(agent_type: str, state: ScanState) -> dict:
    """A small, human-readable summary of what an agent did, stored on the agent_run so the scan
    view can show the pipeline 'thinking' as it runs. The validation step carries the actual
    red/blue deliberation — the transparency that makes the debate visible."""
    if agent_type == "recon":
        return {"summary": f"{len(state.raw_findings)} raw findings, {len(state.detected_services)} services detected"}
    if agent_type == "analyst":
        domains = {classify_domain(f) for f in state.raw_findings}
        return {"summary": f"{len(state.analyzed_findings)} findings analyzed across {len(domains)} domain(s)"}
    if agent_type == "correlation":
        n = sum(1 for f in state.analyzed_findings if f.source_service)
        return {"summary": f"{n} CVE finding(s) correlated from detected services"}
    if agent_type == "threat_intel":
        kev = sum(1 for e in state.enriched_findings if e.exploitability == "active")
        return {"summary": f"{len(state.enriched_findings)} enriched, {kev} actively exploited (KEV)"}
    if agent_type == "validation":
        debates = [
            {
                "title": f.title,
                "verdict": f.verdict,
                "rationale": f.verdict_rationale,
                "red": (f.debate or {}).get("red"),
                "blue": (f.debate or {}).get("blue"),
            }
            for f in state.analyzed_findings if f.verdict
        ]
        fp = sum(1 for d in debates if d["verdict"] == "false_positive")
        debated = sum(1 for d in debates if d["red"] or d["blue"])
        return {
            "summary": f"{len(debates)} finding(s) judged · {debated} debated · {fp} likely false positive",
            "debates": debates[:25],  # bound the payload
        }
    if agent_type == "remediation":
        return {"summary": f"{len(state.remediation_suggestions)} remediation suggestion(s)"}
    if agent_type == "risk_manager":
        return {"summary": f"{len(state.risk_decisions)} risk decision(s) via SSVC"}
    if agent_type == "reporter":
        return {"summary": (state.report.summary if state.report else "")[:300]}
    return {}


def _scan_is_canceled(scan_id: str) -> bool:
    scan = supabase.table("scans").select("status, error_message").eq("id", scan_id).single().execute()
    return bool(scan.data and _scan_row_is_canceled(scan.data))


def _scan_row_is_canceled(scan: dict) -> bool:
    return scan.get("status") == "canceled" or (
        scan.get("status") == "failed" and scan.get("error_message") == "Canceled by user"
    )


def _mark_scan_canceled(scan_id: str) -> None:
    payload = {"status": "canceled", "completed_at": datetime.now(timezone.utc).isoformat()}
    try:
        supabase.table("scans").update(payload).eq("id", scan_id).execute()
    except Exception:
        supabase.table("scans").update(
            {**payload, "status": "failed", "error_message": "Canceled by user"}
        ).eq("id", scan_id).execute()


def _persist_results(state: ScanState):
    """Upsert findings and insert suggestions into Supabase."""
    # Persist the executive scan report (summary + SSVC-ordered priorities) so the scan detail
    # view can show it. Best-effort: a report failure must never lose the findings below.
    if state.report is not None:
        try:
            supabase.table("scans").update(
                {"report": state.report.model_dump()}
            ).eq("id", state.scan_id).execute()
        except Exception:
            logger.exception("failed to persist scan report for %s", state.scan_id)

    # Persist the detected software inventory so Watchtower can re-correlate it daily
    # against newly known-exploited CVEs without re-scanning. Best-effort.
    try:
        from backend.core.inventory import record_inventory

        record_inventory(state.org_id, state.asset.id, state.detected_services)
    except Exception:
        logger.exception("inventory persistence failed for scan %s", state.scan_id)

    from backend.core import ssvc

    for finding in state.analyzed_findings:
        enrichment = next(
            (e for e in state.enriched_findings if e.finding_id == finding.id), None
        )

        # SSVC deployer priority for every finding (not just those with a remediation), so the UI
        # and prioritization have a contextual urgency label. Deterministic, 0 tokens.
        ssvc_result = ssvc.assess(
            exploitability=enrichment.exploitability if enrichment else None,
            public_exploits_exist=bool(enrichment.public_exploits_exist) if enrichment else False,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            is_internal=state.asset.is_internal,
        )

        supabase.table("findings").upsert(
            {
                "org_id": state.org_id,
                "scan_id": state.scan_id,
                "asset_id": state.asset.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score,
                "cve_ids": finding.cve_ids,
                "fingerprint": finding.id,
                "raw_data": {
                    "confidence": finding.confidence,
                    "rationale": finding.rationale,
                    "threat_context": enrichment.threat_context if enrichment else None,
                    "exploitability": enrichment.exploitability if enrichment else None,
                    "source_service": finding.source_service,
                    "ssvc": ssvc_result.as_dict(),
                    "verdict": finding.verdict,
                    "verdict_rationale": finding.verdict_rationale,
                    "debate": finding.debate,
                },
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            on_conflict="org_id,fingerprint",
        ).execute()

    # Insert remediation suggestions
    for suggestion in state.remediation_suggestions:
        decision = next(
            (d for d in state.risk_decisions if d.suggestion_id == suggestion.finding_id), None
        )
        # Look up the DB finding id by fingerprint
        db_finding = (
            supabase.table("findings")
            .select("id")
            .eq("org_id", state.org_id)
            .eq("fingerprint", suggestion.finding_id)
            .single()
            .execute()
        )
        if not db_finding.data:
            continue

        supabase.table("agent_suggestions").insert(
            {
                "org_id": state.org_id,
                "finding_id": db_finding.data["id"],
                "action_type": suggestion.action_type,
                "title": suggestion.title,
                "description": suggestion.description,
                "command_or_patch": suggestion.command_or_patch,
                "confidence_score": suggestion.confidence,
                "estimated_risk": suggestion.estimated_risk,
                "mode": decision.mode if decision else "suggest_only",
                "safety_tier": decision.safety_tier if decision else None,
                "status": "pending",
            }
        ).execute()
