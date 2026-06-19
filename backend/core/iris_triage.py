"""
Iris AI Triage — token-economic risk analysis of host agent events.

Groups raw iris_events by (event_type, severity), sends a compact summary
to the LLM, and creates findings only for HIGH/CRITICAL-risk groups.

Token budget: ~200-400 input tokens regardless of event volume (no payloads,
no raw titles — only counts + 2 representative examples per group).
"""

import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from openai import OpenAI

from backend.core.config import settings
from backend.core.supabase_client import supabase
from backend.core import verdict_memory
from backend.core.token_budget import check_budget

logger = logging.getLogger(__name__)

# In-memory last-run tracker: {org_id: datetime}
_last_run: dict[str, datetime] = {}

_SYSTEM = (
    "You are a host security triage analyst. You receive a compact summary of events "
    "from endpoint monitoring agents. Identify only real threats — lateral movement, "
    "privilege escalation, persistence, data exfiltration, C2 beaconing, credential abuse. "
    "Ignore routine noise: package installs, cron, logrotate, normal SSH logins. "
    "Be conservative: only flag what you are confident is malicious or suspicious."
)

_VALID_RISKS = {"CRITICAL", "HIGH"}


def _llm_client() -> OpenAI:
    return OpenAI(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key or "no-key",
        timeout=min(settings.llm_timeout_seconds, 30.0),
        max_retries=1,
    )


def _severity_from_risk(risk: str) -> str:
    return {"CRITICAL": "critical", "HIGH": "high"}.get(risk, "medium")


def run_iris_triage_for_org(org_id: str, interval_minutes: int = 60) -> dict:
    """
    Run AI triage for one org. Skips if last run is within interval_minutes.
    Returns a summary dict for logging.
    """
    now = datetime.now(timezone.utc)
    last = _last_run.get(org_id)
    if last and (now - last).total_seconds() < interval_minutes * 60:
        return {"skipped": True, "reason": "interval not elapsed"}

    # 1. Fetch pending events (no payloads — token economy)
    rows = (
        supabase.table("iris_events")
        .select("id, event_type, severity, title, agent_id")
        .eq("org_id", org_id)
        .eq("processed", False)
        .limit(2000)
        .execute()
        .data or []
    )
    if not rows:
        _last_run[org_id] = now
        return {"skipped": True, "reason": "no pending events"}

    # 2. Group: {(event_type, severity): [titles...]} + track agents per group
    groups: dict[tuple, list[str]] = defaultdict(list)
    agents_by_group: dict[tuple, set[str]] = defaultdict(set)
    for e in rows:
        key = (e["event_type"], e["severity"])
        groups[key].append(e["title"])
        agents_by_group[key].add(e["agent_id"])

    # 3. Filter groups already known as false positives (org-level + community)
    #    Signature matches the finding title we'd create → same key on record & recall.
    sig_for = {
        (etype, sev): verdict_memory.finding_signature(
            title=f"[Iris AI] Suspicious activity: {etype}/{sev}"
        )
        for etype, sev in groups
    }
    known = verdict_memory.recall(org_id, set(sig_for.values()))
    known.update(verdict_memory.recall_community(set(sig_for.values())))

    skipped_fp = 0
    lines = []
    for (etype, sev), titles in sorted(groups.items(), key=lambda x: -len(x[1])):
        if known.get(sig_for[(etype, sev)]) == "false_positive":
            skipped_fp += 1
            continue
        sample = " | ".join(titles[:2])
        lines.append(f"{len(titles)}x [{sev.upper()}] {etype}: {sample}")
        if len(lines) >= 100:
            break

    if skipped_fp:
        logger.info("iris_triage: org=%s skipped %d known-false-positive groups", org_id, skipped_fp)

    if not lines:
        _last_run[org_id] = now
        return {"skipped": True, "reason": "all groups are known false positives"}

    summary = "\n".join(lines)
    prompt = (
        f"Host agent events summary ({len(rows)} total events, {len(groups)} groups):\n\n"
        f"{summary}\n\n"
        "Reply ONLY with a JSON array. Each element: "
        '{"group": "<event_type>/<severity>", "risk": "CRITICAL|HIGH", "reason": "<one sentence>"}. '
        "Include only groups with CRITICAL or HIGH risk. Empty array if nothing is concerning."
    )

    # 4. Check token budget before calling LLM
    budget = check_budget(org_id)
    if not budget["ok"]:
        logger.warning("iris_triage: org=%s skipped — token budget exceeded (%s)", org_id, budget["period"])
        return {"skipped": True, "reason": f"token budget exceeded ({budget['period']})"}

    # 5. Call LLM
    model = settings.iris_triage_model or settings.llm_default_model
    try:
        client = _llm_client()
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
            max_tokens=600,
        )
        raw = resp.choices[0].message.content or "[]"
    except Exception as exc:
        logger.error("iris_triage: LLM call failed for org %s: %s", org_id, exc)
        return {"error": str(exc)}

    # 5. Parse response
    try:
        # Strip markdown fences if present
        clean = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        findings_data = json.loads(clean)
        if not isinstance(findings_data, list):
            findings_data = []
    except Exception:
        logger.warning("iris_triage: could not parse LLM response for org %s: %s", org_id, raw[:200])
        findings_data = []

    # 6. For each HIGH/CRITICAL group: create triage finding + trigger full pipeline
    from backend.api.iris import _do_process_agent

    created = 0
    pipelines_triggered: set[str] = set()
    today = now.date().isoformat()

    for item in findings_data:
        risk = str(item.get("risk", "")).upper()
        if risk not in _VALID_RISKS:
            continue

        group_key = str(item.get("group", ""))
        reason = str(item.get("reason", ""))[:500]
        group_tuple = tuple(group_key.split("/", 1))

        # Triage alert finding (lightweight, fast)
        fp = hashlib.sha256(f"iris_ai:{org_id}:{group_key}:{today}".encode()).hexdigest()
        try:
            supabase.table("findings").insert({
                "org_id": org_id,
                "title": f"[Iris AI] Suspicious activity: {group_key}",
                "description": reason,
                "severity": _severity_from_risk(risk),
                "status": "open",
                "source": "iris_ai",
                "fingerprint": fp,
                "raw_data": {
                    "tool": "iris_ai",
                    "template_id": f"iris_ai:{group_key}",
                    "group": group_key,
                    "event_count": len(groups.get(group_tuple, [])),
                    "model": model,
                },
                "last_seen_at": now.isoformat(),
            }).execute()
            created += 1
        except Exception as exc:
            logger.debug("iris_triage: finding already exists for %s: %s", group_key, exc)

        # Trigger full pipeline for affected agents (deduplicated)
        for agent_id in agents_by_group.get(group_tuple, set()):
            if agent_id in pipelines_triggered:
                continue
            try:
                _do_process_agent(agent_id, org_id, supabase)
                pipelines_triggered.add(agent_id)
                logger.info("iris_triage: triggered full pipeline for agent %s (risk=%s)", agent_id, risk)
            except Exception as exc:
                logger.warning("iris_triage: pipeline trigger failed for agent %s: %s", agent_id, exc)

    _last_run[org_id] = now
    logger.info(
        "iris_triage: org=%s events=%d groups=%d flagged=%d findings=%d pipelines=%d",
        org_id, len(rows), len(groups), len(findings_data), created, len(pipelines_triggered),
    )
    return {
        "events_analyzed": len(rows),
        "groups": len(groups),
        "flagged": len(findings_data),
        "findings_created": created,
        "pipelines_triggered": len(pipelines_triggered),
        "model": model,
    }


def run_iris_triage_all_orgs(global_interval_minutes: int = 60) -> dict:
    """Run triage for every org that has pending events, respecting per-org intervals."""
    orgs = supabase.table("organizations").select("id").execute().data or []
    results = {}
    for org in orgs:
        org_id = org["id"]
        # Per-org interval from settings (falls back to global)
        interval = global_interval_minutes
        try:
            row = (
                supabase.table("org_settings")
                .select("iris_triage_interval_minutes")
                .eq("org_id", org_id)
                .execute()
                .data or []
            )
            if row and row[0].get("iris_triage_interval_minutes"):
                interval = int(row[0]["iris_triage_interval_minutes"])
        except Exception:
            pass

        try:
            results[org_id] = run_iris_triage_for_org(org_id, interval)
        except Exception as exc:
            logger.error("iris_triage: org %s failed: %s", org_id, exc)
            results[org_id] = {"error": str(exc)}

    return results
