"""
Notification dispatch — Slack + email.

Best-effort by design (like core.audit): a failing or misconfigured integration must
NEVER break a scan. After a scan completes, `notify_scan_complete` builds a findings
summary and pushes it to every enabled integration whose severity threshold is met.

Integration config (stored in the integrations.config jsonb, read with service-role):
  Slack: {"webhook_url": "...", "min_severity": "high"}
  Email: {"to": ["a@b.com"], "min_severity": "high",
          optional SMTP overrides: smtp_host/smtp_port/smtp_user/smtp_password/from_addr/use_tls}
"""

import logging
import smtplib
from email.message import EmailMessage

import httpx

from backend.core.config import settings
from backend.core.supabase_client import supabase  # service-role: reads secrets, bypasses RLS

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_HTTP_TIMEOUT = 15.0


# ── Severity / summary helpers ───────────────────────────────────────────────

def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0


def _meets_threshold(findings: list[dict], min_severity: str) -> bool:
    """True if any finding is >= min_severity, or any is actively exploited (KEV)."""
    threshold = _sev_rank(min_severity)
    for f in findings:
        if _sev_rank(f.get("severity", "info")) >= threshold:
            return True
        if (f.get("raw_data") or {}).get("exploitability") == "active":
            return True
    return False


def _summarize(asset_name: str, findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    kev: list[str] = []
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        if (f.get("raw_data") or {}).get("exploitability") == "active":
            for cve in f.get("cve_ids") or []:
                kev.append(cve)
    return {
        "asset": asset_name,
        "total": len(findings),
        "counts": counts,
        "kev": sorted(set(kev)),
    }


def _counts_line(counts: dict[str, int]) -> str:
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts.get(s)]
    return ", ".join(parts) or "no findings"


# ── Channels ─────────────────────────────────────────────────────────────────

def _slack_post(webhook_url: str, header: str, body: str) -> None:
    payload = {
        "text": f"{header}\n{body}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": header}},
            {"type": "section", "text": {"type": "mrkdwn", "text": body}},
        ],
    }
    resp = httpx.post(webhook_url, json=payload, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()


def send_slack(webhook_url: str, summary: dict) -> None:
    body = f"*{summary['total']} findings*: {_counts_line(summary['counts'])}"
    if summary["kev"]:
        body += "\n🔴 *Actively exploited (CISA KEV):* " + ", ".join(summary["kev"][:10])
    _slack_post(webhook_url, f"🛡️ Scan complete — {summary['asset']}", body)


def send_email(
    config: dict,
    subject: str,
    body: str,
    attachments: list[tuple[str, bytes, str, str]] | None = None,
) -> None:
    """Send an email via the integration's SMTP (or the global fallback).
    `attachments`: list of (filename, data, maintype, subtype), e.g. the board PDF."""
    to = config.get("to") or []
    if not to:
        raise ValueError("email integration has no recipients ('to')")

    host = config.get("smtp_host") or settings.smtp_host
    if not host:
        raise ValueError("no SMTP host configured (integration or global)")
    port = int(config.get("smtp_port") or settings.smtp_port)
    user = config.get("smtp_user") or settings.smtp_user
    password = config.get("smtp_password") or settings.smtp_password
    from_addr = config.get("from_addr") or settings.smtp_from or user
    use_tls = config.get("use_tls", settings.smtp_use_tls)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    for filename, data, maintype, subtype in attachments or []:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    with smtplib.SMTP(host, port, timeout=_HTTP_TIMEOUT) as server:
        if use_tls:
            server.starttls()
        if user and password:
            server.login(user, password)
        server.send_message(msg)


def _email_body(summary: dict) -> tuple[str, str]:
    subject = f"[Horus] Scan complete — {summary['asset']} ({summary['total']} findings)"
    lines = [
        f"Asset: {summary['asset']}",
        f"Total findings: {summary['total']}",
        f"Breakdown: {_counts_line(summary['counts'])}",
    ]
    if summary["kev"]:
        lines.append("")
        lines.append("Actively exploited (CISA KEV):")
        lines.extend(f"  - {cve}" for cve in summary["kev"])
    return subject, "\n".join(lines)


# ── Orchestration ────────────────────────────────────────────────────────────

def _dispatch(integration: dict, summary: dict) -> None:
    itype = integration["type"]
    config = integration.get("config") or {}
    min_sev = config.get("min_severity") or settings.notify_default_min_severity
    if not _meets_threshold(summary["_findings"], min_sev):
        logger.info("notify: %s skipped (below %s threshold)", itype, min_sev)
        return

    if itype == "slack":
        send_slack(config["webhook_url"], summary)
    elif itype == "email":
        subject, body = _email_body(summary)
        send_email(config, subject, body)
    else:
        logger.warning("notify: unknown integration type %r", itype)
        return
    logger.info("notify: %s delivered for asset %s", itype, summary["asset"])


def _notify_in_app(org_id: str, scan_id: str, summary: dict) -> None:
    """Create an in-app notification (the header bell) for each admin/analyst in the org.
    Service-role insert bypasses RLS; users read their own via the notifications API."""
    recipients = (
        supabase.table("profiles")
        .select("id")
        .eq("org_id", org_id)
        .in_("role", ["admin", "analyst"])
        .execute()
        .data
    )
    if not recipients:
        return
    title = f"Scan complete — {summary['asset']}"
    body = f"{summary['total']} findings: {_counts_line(summary['counts'])}"
    if summary["kev"]:
        body += f" · {len(summary['kev'])} actively exploited"
    rows = [
        {
            "org_id": org_id,
            "user_id": r["id"],
            "type": "scan_complete",
            "title": title,
            "body": body,
            "metadata": {"scan_id": scan_id, "kev": summary["kev"]},
        }
        for r in recipients
    ]
    supabase.table("notifications").insert(rows).execute()


def notify_scan_complete(scan_id: str, org_id: str) -> None:
    """Builds a scan summary and notifies: in-app bell + every enabled integration.
    Best-effort throughout — notification failures never affect the scan."""
    scan = (
        supabase.table("scans").select("*, assets(name)").eq("id", scan_id).single().execute().data
    )
    asset_name = (scan.get("assets") or {}).get("name", "unknown asset")
    findings = (
        supabase.table("findings")
        .select("severity, cve_ids, raw_data")
        .eq("scan_id", scan_id)
        .execute()
        .data
    )
    # Don't alert on findings the validation debate judged likely false positives — same
    # suppression the posture score uses, so notifications match the board number.
    from backend.core.posture import is_suppressed
    findings = [f for f in findings if not is_suppressed(f.get("raw_data"))]

    summary = _summarize(asset_name, findings)
    summary["_findings"] = findings  # internal: threshold check only

    # In-app bell: only when the scan meets the default severity bar (avoid flooding it
    # with clean nightly scans). Independent of whether Slack/email is configured.
    if _meets_threshold(findings, settings.notify_default_min_severity):
        try:
            _notify_in_app(org_id, scan_id, summary)
        except Exception:
            logger.exception("notify: in-app notification failed for scan %s", scan_id)

    integrations = (
        supabase.table("integrations").select("*").eq("org_id", org_id).eq("enabled", True).execute().data
    )
    for integration in integrations:
        try:
            _dispatch(integration, summary)
        except Exception:
            logger.exception("notify: integration %s failed", integration.get("id"))


# ── Watchtower alerts ─────────────────────────────────────────────────────────
# Continuous-exposure alerts. Two kinds: a CVE just entered CISA KEV (confirmed exploitation), or
# a CVE's EPSS exploitation probability just spiked (rising risk, an early warning). Both match
# software already in the inventory and are urgent, so — unlike scan summaries — they bypass the
# per-integration severity threshold. The wording differs by kind.

# Per-kind copy: (slack header, in-app title, email subject, lead sentence).
_WATCHTOWER_COPY = {
    "kev_added": (
        "🚨 New active exploitation affecting your stack",
        "🚨 {n} new actively-exploited exposure(s)",
        "[Horus] 🚨 {n} new actively-exploited exposure(s)",
        "CVEs that just entered CISA KEV match software already in your inventory",
    ),
    "epss_spike": (
        "📈 Rising exploitation risk in your stack",
        "📈 {n} CVE(s) with rising exploitation risk",
        "[Horus] 📈 {n} CVE(s) with rising exploitation risk",
        "CVEs whose exploitation probability (EPSS) just spiked match software in your inventory",
    ),
}


def _watchtower_text(cves: list[str], assets: list[str], count: int, kind: str) -> tuple[str, str]:
    header, _, _, lead = _WATCHTOWER_COPY.get(kind, _WATCHTOWER_COPY["kev_added"])
    asset_line = ", ".join(assets[:8]) + (f" +{len(assets) - 8} more" if len(assets) > 8 else "")
    cve_line = ", ".join(cves[:12]) + (f" +{len(cves) - 12} more" if len(cves) > 12 else "")
    body = (
        f"*{count} new exposure(s)* — {lead} (no re-scan needed).\n"
        f"*Affected assets:* {asset_line}\n"
        f"*CVEs:* {cve_line}"
    )
    return header, body


def _notify_watchtower_in_app(
    org_id: str, cves: list[str], assets: list[str], count: int, kind: str
) -> None:
    recipients = (
        supabase.table("profiles")
        .select("id")
        .eq("org_id", org_id)
        .in_("role", ["admin", "analyst"])
        .execute()
        .data
    )
    if not recipients:
        return
    _, title_tmpl, _, lead = _WATCHTOWER_COPY.get(kind, _WATCHTOWER_COPY["kev_added"])
    asset_line = ", ".join(assets[:5]) + (f" +{len(assets) - 5} more" if len(assets) > 5 else "")
    title = title_tmpl.format(n=count)
    body = f"{lead}: {asset_line}"
    rows = [
        {
            "org_id": org_id,
            "user_id": r["id"],
            "type": "watchtower_alert",
            "title": title,
            "body": body,
            "metadata": {"cves": cves, "assets": assets, "reason": kind},
        }
        for r in recipients
    ]
    supabase.table("notifications").insert(rows).execute()


def notify_watchtower(org_id: str, alerts: list[dict], kind: str = "kev_added") -> None:
    """Notify (in-app bell + Slack/email) that inventory assets are newly exposed. `kind` is
    'kev_added' (confirmed exploitation) or 'epss_spike' (rising probability), which selects the
    wording. `alerts`: [{cve_id, product, version, asset_id, severity}]. Best-effort."""
    if not alerts:
        return

    asset_ids = sorted({a["asset_id"] for a in alerts})
    name_rows = (
        supabase.table("assets").select("id, name").in_("id", asset_ids).execute().data or []
    )
    names = {r["id"]: r["name"] for r in name_rows}
    assets = sorted({names.get(a["asset_id"], "asset") for a in alerts})
    cves = sorted({a["cve_id"] for a in alerts})
    count = len(alerts)

    try:
        _notify_watchtower_in_app(org_id, cves, assets, count, kind)
    except Exception:
        logger.exception("notify_watchtower: in-app notification failed for org %s", org_id)

    header, body = _watchtower_text(cves, assets, count, kind)
    _, _, subject_tmpl, lead = _WATCHTOWER_COPY.get(kind, _WATCHTOWER_COPY["kev_added"])
    integrations = (
        supabase.table("integrations").select("*").eq("org_id", org_id).eq("enabled", True).execute().data
    )
    for integration in integrations:
        itype = integration["type"]
        config = integration.get("config") or {}
        try:
            if itype == "slack":
                _slack_post(config["webhook_url"], header, body)
            elif itype == "email":
                subject = subject_tmpl.format(n=count)
                email_body = (
                    f"{count} new exposure(s): {lead} (no re-scan needed).\n\n"
                    f"Affected assets:\n" + "\n".join(f"  - {a}" for a in assets) + "\n\n"
                    f"CVEs:\n" + "\n".join(f"  - {c}" for c in cves)
                )
                send_email(config, subject, email_body)
            else:
                continue
            logger.info("notify_watchtower: %s delivered for org %s (%s)", itype, org_id, kind)
        except Exception:
            logger.exception("notify_watchtower: integration %s failed", integration.get("id"))


# ── Board posture report (PDF over email) ──────────────────────────────────────
# The executive risk timeline, rendered to a board-ready PDF and emailed to recipients who
# opted in (email integration config: {"posture_report": true}). Runs monthly on a cron, and
# on demand from the dashboard. The same defensible, deterministic score behind the chart —
# now it lands in the board's inbox without anyone logging in.

def _posture_email_body(org_name: str, data: dict, days: int) -> tuple[str, str]:
    current = data.get("current") or {}
    delta = int(data.get("trend_delta") or 0)
    score = current.get("risk_score", "—")
    if delta < 0:
        trend = f"down {abs(delta)} points"
    elif delta > 0:
        trend = f"up {delta} points"
    else:
        trend = "unchanged"
    subject = f"[Horus] Security posture report — {org_name}"
    body = (
        f"Attached is the board-ready security posture report for {org_name}.\n\n"
        f"Current risk score: {score} ({trend} over the last {days} days; lower is better).\n"
        f"Open findings: {current.get('open_findings', 0)}"
        + (f", of which {current['kev_active']} are actively exploited (CISA KEV)."
           if current.get("kev_active") else ".")
        + "\n\nThe attached PDF has the full trend chart, severity breakdown, and how the score "
        "is computed. Generated automatically by Horus continuous monitoring.\n"
    )
    return subject, body


def send_posture_report(org_id: str, days: int = 90) -> int:
    """Build the board PDF for one org and email it to every enabled email integration that
    opted into board reports. Returns how many integrations it was sent to. Best-effort per
    integration. Service-role reads (cron + on-demand admin trigger both land here)."""
    from backend.core.posture import load_timeline
    from backend.core.posture_report import build_posture_pdf

    integrations = (
        supabase.table("integrations")
        .select("*")
        .eq("org_id", org_id)
        .eq("type", "email")
        .eq("enabled", True)
        .execute()
        .data
        or []
    )
    targets = [i for i in integrations if (i.get("config") or {}).get("posture_report")]
    if not targets:
        return 0

    data = load_timeline(supabase, org_id, days)
    if not data.get("current"):
        logger.info("posture report: org %s has no posture history yet, skipping", org_id)
        return 0

    org = supabase.table("organizations").select("name").eq("id", org_id).single().execute().data or {}
    org_name = org.get("name") or "your organization"

    pdf = build_posture_pdf({"org_name": org_name, "days": days, **data})
    from datetime import datetime, timezone
    filename = f"posture-report-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    subject, body = _posture_email_body(org_name, data, days)

    sent = 0
    for integration in targets:
        try:
            send_email(
                integration.get("config") or {},
                subject,
                body,
                attachments=[(filename, pdf, "application", "pdf")],
            )
            sent += 1
            logger.info("posture report: emailed org %s integration %s", org_id, integration.get("id"))
        except Exception:
            logger.exception("posture report: integration %s failed", integration.get("id"))
    return sent


def send_all_posture_reports(days: int = 90) -> int:
    """Cron entry point: email the board report to every org that has an opted-in email
    integration. Returns the number of integrations delivered to across all orgs."""
    rows = (
        supabase.table("integrations")
        .select("org_id, config, enabled, type")
        .eq("type", "email")
        .eq("enabled", True)
        .execute()
        .data
        or []
    )
    org_ids = sorted({r["org_id"] for r in rows if (r.get("config") or {}).get("posture_report")})
    total = 0
    for org_id in org_ids:
        try:
            total += send_posture_report(org_id, days)
        except Exception:
            logger.exception("posture report: org %s failed", org_id)
    logger.info("posture report: delivered to %d integration(s) across %d org(s)", total, len(org_ids))
    return total


def send_test(integration: dict) -> None:
    """Sends a fixed test message to validate an integration's config. Raises on failure."""
    itype = integration["type"]
    config = integration.get("config") or {}
    if itype == "slack":
        _slack_post(
            config["webhook_url"],
            "✅ Horus test",
            "Your Slack integration works. You'll get scan alerts here.",
        )
    elif itype == "email":
        send_email(
            config,
            "[Horus] Test notification",
            "This is a test notification from Horus. Your integration works. ✅",
        )
    else:
        raise ValueError(f"unknown integration type: {itype}")
