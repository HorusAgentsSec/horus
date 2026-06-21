"""AWS CloudTrail detections — pure, mocked events, no boto3."""

from backend.core.cloud import aws_cloudtrail as ct


def _ev(**kw):
    base = {"event_name": "", "event_id": "e1", "username": "u", "user_type": "IAMUser",
            "source_ip": "1.2.3.4", "event_time": "t", "request_params": {}, "error_code": None}
    base.update(kw)
    return base


def test_root_activity():
    f = ct.classify_event(_ev(event_name="RunInstances", user_type="Root"))
    assert f and f.check_id == "ct_root_activity" and f.severity == "high"


def test_root_console_login():
    f = ct.classify_event(_ev(event_name="ConsoleLogin", user_type="Root"))
    assert f and f.check_id == "ct_root_activity"


def test_trail_tampering_is_critical():
    for name in ("StopLogging", "DeleteTrail"):
        f = ct.classify_event(_ev(event_name=name))
        assert f and f.check_id == "ct_trail_tampering" and f.severity == "critical"


def test_detection_tampering():
    f = ct.classify_event(_ev(event_name="DeleteDetector"))
    assert f and f.check_id == "ct_detection_tampering"


def test_admin_grant_only_for_admin_policy():
    admin = ct.classify_event(_ev(event_name="AttachUserPolicy",
                                  request_params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    assert admin and admin.check_id == "ct_admin_grant"
    scoped = ct.classify_event(_ev(event_name="AttachUserPolicy",
                                   request_params={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    assert scoped is None


def test_access_key_and_user_creation():
    assert ct.classify_event(_ev(event_name="CreateAccessKey")).check_id == "ct_access_key_created"
    assert ct.classify_event(_ev(event_name="CreateUser")).check_id == "ct_new_iam_user"


def test_security_group_opened_to_world():
    opened = _ev(event_name="AuthorizeSecurityGroupIngress",
                 request_params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})
    f = ct.classify_event(opened)
    assert f and f.check_id == "ct_sg_opened"
    scoped = _ev(event_name="AuthorizeSecurityGroupIngress",
                 request_params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}})
    assert ct.classify_event(scoped) is None


def test_failed_console_login():
    f = ct.classify_event(_ev(event_name="ConsoleLogin", error_code="Failed authentication"))
    assert f and f.check_id == "ct_console_login_failed"


def test_routine_event_ignored():
    assert ct.classify_event(_ev(event_name="DescribeInstances", user_type="IAMUser")) is None


def test_evaluate_events_filters_and_fingerprints():
    events = [
        _ev(event_name="DescribeInstances", event_id="a"),       # ignored
        _ev(event_name="StopLogging", event_id="b"),             # critical
        _ev(event_name="CreateAccessKey", event_id="c"),         # medium
    ]
    findings = ct.evaluate_events(events)
    assert len(findings) == 2
    assert {f.dedup_key for f in findings} == {"aws:ct_trail_tampering:b", "aws:ct_access_key_created:c"}
