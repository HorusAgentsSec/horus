"""AWS security checks — pure, mocked inventory, no boto3 / no credentials."""

from backend.core.cloud import aws_checks as c


def _ids(findings):
    return {f.check_id for f in findings}


def test_s3_public_and_unencrypted():
    data = {"s3_buckets": [
        {"name": "leaky", "public_access_block_all": False, "policy_is_public": True, "encryption_enabled": False},
        {"name": "safe", "public_access_block_all": True, "policy_is_public": False, "encryption_enabled": True},
    ]}
    ids = _ids(c.evaluate(data))
    assert "s3_public_bucket" in ids
    assert "s3_no_encryption" in ids
    # The safe bucket must not generate either finding.
    pub = c.check_s3_public(data)
    assert [f.resource for f in pub] == ["leaky"]


def test_iam_mfa_only_for_console_users():
    data = {"iam_users": [
        {"user_name": "alice", "has_console_password": True, "mfa_enabled": False, "access_keys": []},
        {"user_name": "bob", "has_console_password": True, "mfa_enabled": True, "access_keys": []},
        {"user_name": "svc", "has_console_password": False, "mfa_enabled": False, "access_keys": []},
    ]}
    res = c.check_iam_mfa(data)
    assert [f.resource for f in res] == ["alice"]


def test_iam_stale_key():
    data = {"iam_users": [
        {"user_name": "alice", "has_console_password": False, "mfa_enabled": False,
         "access_keys": [{"key_id": "AKIA1", "active": True, "last_used_days": 200},
                         {"key_id": "AKIA2", "active": True, "last_used_days": 5},
                         {"key_id": "AKIA3", "active": False, "last_used_days": 999}]},
    ]}
    res = c.check_iam_stale_keys(data)
    assert [f.resource for f in res] == ["alice:AKIA1"]


def test_root_account_checks():
    bad = {"root_account": {"access_keys_present": True, "mfa_enabled": False}}
    assert _ids(c.evaluate(bad)) >= {"root_access_keys", "root_no_mfa"}
    good = {"root_account": {"access_keys_present": False, "mfa_enabled": True}}
    assert c.check_root_access_keys(good) == []
    assert c.check_root_mfa(good) == []


def test_security_group_sensitive_port_open():
    data = {"security_groups": [
        {"group_id": "sg-1", "group_name": "web", "open_ingress": [
            {"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"},     # SSH open → critical
            {"port": 443, "cidr": "0.0.0.0/0", "protocol": "tcp"},    # HTTPS → not flagged
            {"port": 3306, "cidr": "10.0.0.0/8", "protocol": "tcp"},  # MySQL but private → not flagged
        ]},
    ]}
    res = c.check_security_groups(data)
    assert len(res) == 1
    assert res[0].severity == "critical"
    assert res[0].resource == "sg-1:22"


def test_codebuild_privileged_and_plaintext_secret():
    data = {"codebuild_projects": [
        {"name": "build", "privileged_mode": True, "env_vars": [
            {"name": "AWS_SECRET_ACCESS_KEY", "type": "PLAINTEXT", "value": "abc"},
            {"name": "DB_PASSWORD", "type": "SECRETS_MANAGER", "value": "arn:..."},  # safe
            {"name": "LOG_LEVEL", "type": "PLAINTEXT", "value": "info"},             # not a secret
        ]},
    ]}
    ids = _ids(c.evaluate(data))
    assert "codebuild_privileged" in ids
    secrets = c.check_codebuild_plaintext_secrets(data)
    assert [f.resource for f in secrets] == ["build:AWS_SECRET_ACCESS_KEY"]


def test_dedup_key_is_stable_and_resource_scoped():
    f = c.CloudFinding("s3_public_bucket", "t", "high", "leaky", "d", "r", "s3", "cspm")
    assert f.dedup_key == "aws:s3_public_bucket:leaky"


def test_empty_inventory_yields_nothing():
    assert c.evaluate({}) == []
