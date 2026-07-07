"""
Adversarial cycle orchestrator — runs RedAgent then BlueAgent for each org.

Follows the same pattern as watchtower.py:
  - run_adversarial_cycle(org_id=None) for all orgs, or a specific one.
  - Called by the cron job in scheduler.py and by the manual trigger in the API.
"""

import logging
from typing import Callable, Optional

from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def run_adversarial_cycle(
    org_id: str | None = None,
    run_id: str | None = None,
    emit: Optional[Callable[[dict], None]] = None,
    job_id: str | None = None,
) -> dict:
    """
    Run RedAgent → BlueAgent for one org or all orgs.
    Returns aggregated counts.
    """
    from backend.agents.red_agent import RedAgent
    from backend.agents.blue_agent import BlueAgent
    from backend.core import cancel
    from backend.core.token_budget import check_budget

    def _emit(event: dict) -> None:
        if emit:
            emit(event)

    if org_id:
        org_ids = [org_id]
    else:
        rows = supabase.table("organizations").select("id").execute().data or []
        org_ids = [r["id"] for r in rows]

    total_findings = 0
    total_responses = 0

    for oid in org_ids:
        if cancel.is_canceled(job_id):
            logger.info("Adversarial cycle canceled before org %s", oid)
            break

        # The Red/Blue tool-loops make many LLM calls; honor the org token budget
        # like the scan pipeline does, or a single org could blow past its limit.
        if not check_budget(oid)["ok"]:
            logger.warning("Adversarial cycle skipped for org %s — token budget exceeded", oid)
            _emit({"type": "error", "message": "Token budget exceeded for this org"})
            continue

        logger.info("Adversarial cycle starting for org %s", oid)
        red_count = 0
        blue_count = 0

        try:
            _emit({"type": "agent_start", "agent": "red"})
            red = RedAgent()
            red_result = red.run_for_org(oid, run_id=run_id, emit=emit, job_id=job_id)
            red_count = red_result.get("findings_created", 0)
            total_findings += red_count
            _emit({"type": "agent_done", "agent": "red", "count": red_count})
        except Exception:
            logger.exception("RedAgent failed for org %s", oid)
            _emit({"type": "error", "agent": "red", "message": "Red agent encountered an error"})

        if cancel.is_canceled(job_id):
            logger.info("Adversarial cycle canceled before blue agent for org %s", oid)
            break

        try:
            _emit({"type": "agent_start", "agent": "blue"})
            blue = BlueAgent()
            blue_result = blue.run_for_org(oid, emit=emit, job_id=job_id)
            blue_count = blue_result.get("responses_created", 0)
            total_responses += blue_count
            _emit({"type": "agent_done", "agent": "blue", "count": blue_count})
        except Exception:
            logger.exception("BlueAgent failed for org %s", oid)
            _emit({"type": "error", "agent": "blue", "message": "Blue agent encountered an error"})

        logger.info(
            "Adversarial cycle done for org %s — %d findings, %d responses",
            oid, red_count, blue_count,
        )

    result = {
        "orgs_processed": len(org_ids),
        "findings_created": total_findings,
        "responses_created": total_responses,
    }
    _emit({"type": "done", **result})
    return result
