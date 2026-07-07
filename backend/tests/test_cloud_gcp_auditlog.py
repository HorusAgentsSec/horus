"""GCP audit log detections — pure, mocked entries, no SDK."""

from backend.core.cloud import gcp_auditlog as al


def _ev(method, request=None, insert_id="i1"):
    return {"method_name": method, "principal": "u@x.com", "caller_ip": "1.2.3.4",
            "timestamp": "t", "insert_id": insert_id, "request": request or {}}


def test_log_sink_tampering_is_critical():
    f = al.classify_event(_ev("google.logging.v2.ConfigServiceV2.DeleteSink"))
    assert f and f.check_id == "gcp_log_tampering" and f.severity == "critical"


def test_service_account_key_created():
    f = al.classify_event(_ev("google.iam.admin.v1.CreateServiceAccountKey"))
    assert f and f.check_id == "gcp_sa_key_created"


def test_firewall_opened_to_world():
    opened = _ev("v1.compute.firewalls.insert", request={"sourceRanges": ["0.0.0.0/0"]})
    assert al.classify_event(opened).check_id == "gcp_firewall_opened"
    scoped = _ev("v1.compute.firewalls.insert", request={"sourceRanges": ["10.0.0.0/8"]})
    assert al.classify_event(scoped) is None


def test_setiam_public_vs_regular_change():
    pub = _ev("storage.setIamPolicy", request={"policy": {"bindings": [{"members": ["allUsers"]}]}})
    assert al.classify_event(pub).check_id == "gcp_made_public"
    regular = _ev("SetIamPolicy", request={"policy": {"bindings": [{"members": ["user:a@b.com"]}]}})
    assert al.classify_event(regular).check_id == "gcp_iam_change"


def test_routine_event_ignored():
    assert al.classify_event(_ev("storage.objects.get")) is None


def test_evaluate_filters_and_fingerprints():
    events = [
        _ev("storage.objects.get", insert_id="a"),                      # ignored
        _ev("google.logging.v2.ConfigServiceV2.DeleteSink", insert_id="b"),  # critical
    ]
    findings = al.evaluate_events(events)
    assert len(findings) == 1
    assert findings[0].dedup_key == "gcp:gcp_log_tampering:b"
