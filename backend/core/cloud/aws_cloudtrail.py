"""
AWS CloudTrail log detections — the pure evaluation layer.

Where aws_checks audits *configuration* (a snapshot), this audits *activity*: recent CloudTrail
events that signal compromise or risky change — root usage, trail tampering, admin grants, new
credentials, security groups opened to the world. classify_event takes one normalized event (see
aws_collect.collect_cloudtrail for the shape) and returns a CloudFinding or None. Pure and
unit-tested; no boto3.

Each finding's resource is the CloudTrail event id, so re-auditing the same window upserts the same
finding instead of duplicating (and distinct events stay distinct).
"""

from typing import Optional

from backend.core.cloud.finding import CloudFinding

# Events that blind or weaken detection/audit — tampering with the security plumbing itself.
_TRAIL_TAMPER = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}
_DETECTION_TAMPER = {"DeleteDetector", "DisassociateMembers", "StopMonitoringMembers",
                     "DeleteConfigRule", "DeleteFlowLogs"}
# IAM changes that grant or create standing access.
_ADMIN_POLICY_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
                        "PutUserPolicy", "PutRolePolicy"}


def _f(check_id, title, severity, event, payload_extra=None) -> CloudFinding:
    desc = (f"CloudTrail event {event.get('event_name')} by {event.get('username') or event.get('user_type') or 'unknown'} "
            f"from {event.get('source_ip') or 'unknown IP'} at {event.get('event_time')}.")
    return CloudFinding(
        check_id, title, severity, event.get("event_id", event.get("event_name", "unknown")),
        desc, _REMEDIATION.get(check_id, "Review this activity and confirm it was authorized."),
        "cloudtrail", "logs", provider="aws",
    )


_REMEDIATION = {
    "ct_root_activity": "Avoid using the root account; lock away its credentials and operate via IAM roles.",
    "ct_trail_tampering": "Confirm this change was intended; CloudTrail must stay enabled. Restrict cloudtrail:* to break-glass roles.",
    "ct_detection_tampering": "Confirm this was intended; restore GuardDuty/Config/flow logs and restrict who can disable them.",
    "ct_admin_grant": "Verify the admin grant was authorized; prefer scoped policies over AdministratorAccess.",
    "ct_access_key_created": "Confirm the new access key is expected; prefer short-lived credentials / roles.",
    "ct_new_iam_user": "Confirm the new IAM user is expected and follows least privilege.",
    "ct_sg_opened": "Confirm the ingress change; never open management ports to 0.0.0.0/0.",
    "ct_console_login_failed": "Investigate repeated failures (possible credential stuffing) and ensure MFA is enforced.",
}


def classify_event(event: dict) -> Optional[CloudFinding]:
    """Map one normalized CloudTrail event to a finding, or None if it's not noteworthy."""
    name = event.get("event_name", "")
    params = event.get("request_params") or {}

    # Root account usage — root should be effectively never used.
    if event.get("user_type") == "Root" and name != "ConsoleLogin":
        return _f("ct_root_activity", f"Root account used: {name}", "high", event)
    if name == "ConsoleLogin" and event.get("user_type") == "Root":
        return _f("ct_root_activity", "Root account console login", "high", event)

    if name in _TRAIL_TAMPER:
        return _f("ct_trail_tampering", f"CloudTrail logging changed: {name}", "critical", event)
    if name in _DETECTION_TAMPER:
        return _f("ct_detection_tampering", f"Security monitoring weakened: {name}", "critical", event)

    if name in _ADMIN_POLICY_EVENTS and "AdministratorAccess" in str(params.get("policyArn", "")):
        return _f("ct_admin_grant", f"AdministratorAccess granted via {name}", "high", event)

    if name == "CreateAccessKey":
        return _f("ct_access_key_created", "New IAM access key created", "medium", event)
    if name == "CreateUser":
        return _f("ct_new_iam_user", "New IAM user created", "medium", event)

    if name == "AuthorizeSecurityGroupIngress" and _opens_to_world(params):
        return _f("ct_sg_opened", "Security group opened to 0.0.0.0/0", "high", event)

    if name == "ConsoleLogin" and event.get("error_code"):
        return _f("ct_console_login_failed", "Failed console login", "medium", event)

    return None


def _opens_to_world(params: dict) -> bool:
    """True if AuthorizeSecurityGroupIngress params include a 0.0.0.0/0 (or ::/0) source."""
    blob = str(params)
    return "0.0.0.0/0" in blob or "::/0" in blob


def evaluate_events(events: list[dict]) -> list[CloudFinding]:
    """Classify a batch of CloudTrail events; drop the unremarkable ones."""
    out = []
    for e in events:
        try:
            f = classify_event(e)
        except Exception:
            continue
        if f is not None:
            out.append(f)
    return out
