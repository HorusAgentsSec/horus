"""GCP security checks — pure, mocked inventory, no SDK / no credentials."""

from backend.core.cloud import gcp_checks as g


def _ids(findings):
    return {f.check_id for f in findings}


def test_storage_public_and_uniform_access():
    data = {"storage_buckets": [
        {"name": "open", "public": True, "uniform_bucket_level_access": False},
        {"name": "locked", "public": False, "uniform_bucket_level_access": True},
    ]}
    assert [f.resource for f in g.check_storage_public(data)] == ["open"]
    assert [f.resource for f in g.check_storage_uniform_access(data)] == ["open"]
    # The provider is gcp, so dedup keys never collide with AWS.
    assert g.check_storage_public(data)[0].dedup_key == "gcp:gcs_public_bucket:open"


def test_service_account_user_managed_keys():
    data = {"service_accounts": [
        {"email": "svc@p.iam.gserviceaccount.com", "user_managed_key_count": 2},
        {"email": "clean@p.iam.gserviceaccount.com", "user_managed_key_count": 0},
    ]}
    res = g.check_sa_user_managed_keys(data)
    assert [f.resource for f in res] == ["svc@p.iam.gserviceaccount.com"]


def test_primitive_roles_only_for_humans():
    data = {"iam_bindings": [
        {"role": "roles/owner", "members": ["user:a@b.com", "serviceAccount:x@p.iam"]},
        {"role": "roles/editor", "members": ["serviceAccount:only@p.iam"]},  # no humans → skip
        {"role": "roles/viewer", "members": ["user:c@b.com"]},               # not primitive → skip
    ]}
    res = g.check_primitive_roles(data)
    assert [f.resource for f in res] == ["roles/owner"]
    assert res[0].severity == "high"


def test_firewall_open_sensitive_port():
    data = {"firewall_rules": [
        {"name": "allow-ssh", "open_ingress": [
            {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},
            {"port": 443, "cidr": "0.0.0.0/0", "protocol": "tcp"},   # not sensitive
            {"port": 3306, "cidr": "10.0.0.0/8", "protocol": "tcp"}, # private
        ]},
    ]}
    res = g.check_firewall_open(data)
    assert len(res) == 1
    assert res[0].resource == "allow-ssh:22"
    assert res[0].severity == "critical"


def test_cloudsql_public():
    data = {"sql_instances": [
        {"name": "db1", "public_ip": True, "authorized_networks": ["0.0.0.0/0"]},
        {"name": "db2", "public_ip": True, "authorized_networks": ["203.0.113.0/24"]},  # scoped
        {"name": "db3", "public_ip": False, "authorized_networks": ["0.0.0.0/0"]},       # no public ip
    ]}
    assert [f.resource for f in g.check_sql_public(data)] == ["db1"]


def test_cloudbuild_default_sa():
    data = {"cloudbuild_triggers": [
        {"name": "deploy", "uses_default_sa": True},
        {"name": "test", "uses_default_sa": False},
    ]}
    assert [f.resource for f in g.check_cloudbuild_default_sa(data)] == ["deploy"]


def test_evaluate_aggregates_and_empty_is_clean():
    assert g.evaluate({}) == []
    data = {"storage_buckets": [{"name": "open", "public": True, "uniform_bucket_level_access": True}],
            "cloudbuild_triggers": [{"name": "deploy", "uses_default_sa": True}]}
    assert _ids(g.evaluate(data)) == {"gcs_public_bucket", "cloudbuild_default_sa"}
