"""
GCP Cloud Audit Log detections — the pure evaluation layer (mirror of aws_cloudtrail).

Scans recent admin-activity audit log entries for risky changes: logging-sink tampering, IAM policy
changes, new service-account keys, firewalls opened to the world, buckets made public.
classify_event takes one normalized entry (see gcp_collect.collect_audit_logs) and returns a
CloudFinding or None. Pure and unit-tested; no SDK.

Each finding's resource is the log entry's insertId, so re-auditing the same window upserts rather
than duplicates.
"""

from typing import Optional

from backend.core.cloud.finding import CloudFinding

_REMEDIATION = {
    "gcp_log_tampering": "Confirm this was intended; audit log sinks must stay in place. Restrict logging.admin.",
    "gcp_iam_change": "Verify the IAM change was authorized; watch for new owners/editors or external members.",
    "gcp_sa_key_created": "Confirm the new service-account key is expected; prefer workload identity / short-lived creds.",
    "gcp_sa_created": "Confirm the new service account is expected and least-privilege.",
    "gcp_firewall_opened": "Confirm the firewall change; never open management ports to 0.0.0.0/0.",
    "gcp_made_public": "Confirm the resource should be public; remove allUsers/allAuthenticatedUsers otherwise.",
}


def _f(check_id, title, severity, event) -> CloudFinding:
    desc = (f"Audit log {event.get('method_name')} by {event.get('principal') or 'unknown'} "
            f"from {event.get('caller_ip') or 'unknown IP'} at {event.get('timestamp')}.")
    return CloudFinding(
        check_id, title, severity, event.get("insert_id", event.get("method_name", "unknown")),
        desc, _REMEDIATION.get(check_id, "Review this activity and confirm it was authorized."),
        "auditlog", "logs", provider="gcp",
    )


def classify_event(event: dict) -> Optional[CloudFinding]:
    """Map one normalized GCP audit log entry to a finding, or None if unremarkable."""
    method = event.get("method_name", "")
    request = event.get("request") or {}
    blob = str(request)

    if "DeleteSink" in method or "UpdateSink" in method:
        return _f("gcp_log_tampering", f"Audit logging changed: {method}", "critical", event)

    if "CreateServiceAccountKey" in method:
        return _f("gcp_sa_key_created", "New service-account key created", "medium", event)
    if "CreateServiceAccount" in method:
        return _f("gcp_sa_created", "New service account created", "medium", event)

    if "firewalls.insert" in method or "firewalls.patch" in method:
        if "0.0.0.0/0" in blob or "::/0" in blob:
            return _f("gcp_firewall_opened", "Firewall opened to 0.0.0.0/0", "high", event)

    if method.endswith("SetIamPolicy") or "setIamPolicy" in method:
        if "allUsers" in blob or "allAuthenticatedUsers" in blob:
            return _f("gcp_made_public", "Resource IAM opened to allUsers", "high", event)
        return _f("gcp_iam_change", f"IAM policy changed: {method}", "medium", event)

    return None


def evaluate_events(events: list[dict]) -> list[CloudFinding]:
    """Classify a batch of audit log entries; drop the unremarkable ones."""
    out = []
    for e in events:
        try:
            f = classify_event(e)
        except Exception:
            continue
        if f is not None:
            out.append(f)
    return out
