"""
AWS inventory collection — the effectful layer (boto3).

Reads a read-only snapshot of the account and returns the plain-dict inventory that aws_checks
evaluates. Kept separate from the checks so the checks stay pure/testable and credentials only ever
touch this module. Every per-resource call is wrapped: one inaccessible bucket or denied API must
not abort the whole audit (partial inventory > no audit).

Credentials come from the integration config (access key + secret, optionally a region). boto3 is an
optional dependency — imported lazily so the rest of the app runs without it installed.
"""

import logging

logger = logging.getLogger(__name__)


def build_session(config: dict):
    """Create a boto3 Session from an integration's stored config. Raises if boto3 is missing."""
    import boto3  # lazy: only needed when an AWS audit actually runs

    return boto3.Session(
        aws_access_key_id=config.get("access_key_id"),
        aws_secret_access_key=config.get("secret_access_key"),
        aws_session_token=config.get("session_token") or None,
        region_name=config.get("region") or "us-east-1",
    )


def collect(session) -> dict:
    """Collect the read-only inventory the checks need. Best-effort per service."""
    sts = session.client("sts")
    account_id = sts.get_caller_identity().get("Account", "unknown")
    return {
        "account_id": account_id,
        "s3_buckets": _collect_s3(session),
        "iam_users": _collect_iam_users(session),
        "root_account": _collect_root(session),
        "security_groups": _collect_security_groups(session),
        "codebuild_projects": _collect_codebuild(session),
    }


def _collect_s3(session) -> list[dict]:
    s3 = session.client("s3")
    out = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        logger.warning("AWS collect: list_buckets failed: %s", e)
        return out
    for b in buckets:
        name = b["Name"]
        out.append({
            "name": name,
            "public_access_block_all": _s3_pab_all(s3, name),
            "policy_is_public": _s3_policy_public(s3, name),
            "encryption_enabled": _s3_encrypted(s3, name),
        })
    return out


def _s3_pab_all(s3, name: str) -> bool:
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        return all(cfg.get(k, False) for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
    except Exception:
        return False  # no PAB config => not fully blocked


def _s3_policy_public(s3, name: str) -> bool:
    try:
        return s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic", False)
    except Exception:
        return False  # no policy => not public via policy


def _s3_encrypted(s3, name: str) -> bool:
    try:
        s3.get_bucket_encryption(Bucket=name)
        return True
    except Exception:
        return False


def _collect_iam_users(session) -> list[dict]:
    iam = session.client("iam")
    out = []
    try:
        users = iam.list_users().get("Users", [])
    except Exception as e:
        logger.warning("AWS collect: list_users failed: %s", e)
        return out
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for u in users:
        name = u["UserName"]
        out.append({
            "user_name": name,
            "has_console_password": _iam_has_password(iam, name),
            "mfa_enabled": _iam_has_mfa(iam, name),
            "access_keys": _iam_keys(iam, name, now),
        })
    return out


def _iam_has_password(iam, name: str) -> bool:
    try:
        iam.get_login_profile(UserName=name)
        return True
    except Exception:
        return False


def _iam_has_mfa(iam, name: str) -> bool:
    try:
        return bool(iam.list_mfa_devices(UserName=name).get("MFADevices"))
    except Exception:
        return False


def _iam_keys(iam, name: str, now) -> list[dict]:
    out = []
    try:
        keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
    except Exception:
        return out
    for k in keys:
        kid = k["AccessKeyId"]
        last_used_days = None
        try:
            used = iam.get_access_key_last_used(AccessKeyId=kid)["AccessKeyLastUsed"].get("LastUsedDate")
            if used:
                last_used_days = (now - used).days
        except Exception:
            pass
        out.append({
            "key_id": kid,
            "active": k.get("Status") == "Active",
            "last_used_days": last_used_days,
        })
    return out


def _collect_root(session) -> dict:
    """Root account posture from the IAM account summary (no root credentials needed)."""
    iam = session.client("iam")
    try:
        s = iam.get_account_summary().get("SummaryMap", {})
        return {
            "access_keys_present": s.get("AccountAccessKeysPresent", 0) > 0,
            "mfa_enabled": s.get("AccountMFAEnabled", 0) > 0,
        }
    except Exception as e:
        logger.warning("AWS collect: get_account_summary failed: %s", e)
        return {}


def _collect_security_groups(session) -> list[dict]:
    ec2 = session.client("ec2")
    out = []
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except Exception as e:
        logger.warning("AWS collect: describe_security_groups failed: %s", e)
        return out
    for sg in sgs:
        open_ingress = []
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            protocol = perm.get("IpProtocol")
            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
            cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
            for cidr in cidrs:
                # A rule can span a port range; emit each known-sensitive port it covers.
                if from_port is None:  # all ports (protocol -1)
                    continue
                for port in range(from_port, (to_port or from_port) + 1):
                    open_ingress.append({"port": port, "cidr": cidr, "protocol": protocol})
                    if to_port and to_port - from_port > 1000:
                        break  # don't expand absurd ranges; the first ports are enough to flag
        out.append({
            "group_id": sg.get("GroupId"),
            "group_name": sg.get("GroupName"),
            "open_ingress": open_ingress,
        })
    return out


def collect_cloudtrail(session, lookback_hours: int = 24, max_events: int = 2000) -> list[dict]:
    """Recent CloudTrail management events, normalized for aws_cloudtrail.classify_event.

    Bounded by both a time window and a hard event cap so a busy account can't pull an unbounded
    page set into memory. Best-effort: any failure returns an empty list."""
    import json
    from datetime import datetime, timedelta, timezone

    out: list[dict] = []
    try:
        ct = session.client("cloudtrail")
        start = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        paginator = ct.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=start):
            for e in page.get("Events", []):
                try:
                    detail = json.loads(e.get("CloudTrailEvent", "{}"))
                except (ValueError, TypeError):
                    detail = {}
                out.append({
                    "event_id": e.get("EventId"),
                    "event_name": e.get("EventName"),
                    "event_time": str(e.get("EventTime", "")),
                    "username": e.get("Username"),
                    "event_source": e.get("EventSource"),
                    "user_type": (detail.get("userIdentity") or {}).get("type"),
                    "source_ip": detail.get("sourceIPAddress"),
                    "request_params": detail.get("requestParameters") or {},
                    "error_code": detail.get("errorCode"),
                })
                if len(out) >= max_events:
                    return out
    except Exception as e:
        logger.warning("AWS collect: cloudtrail lookup_events failed: %s", e)
    return out


def _collect_codebuild(session) -> list[dict]:
    cb = session.client("codebuild")
    out = []
    try:
        names = cb.list_projects().get("projects", [])
        if not names:
            return out
        projects = cb.batch_get_projects(names=names).get("projects", [])
    except Exception as e:
        logger.warning("AWS collect: codebuild list failed: %s", e)
        return out
    for p in projects:
        env = p.get("environment", {})
        out.append({
            "name": p.get("name"),
            "privileged_mode": env.get("privilegedMode", False),
            "env_vars": [
                {"name": v.get("name"), "type": v.get("type", "PLAINTEXT"), "value": v.get("value")}
                for v in env.get("environmentVariables", [])
            ],
        })
    return out
