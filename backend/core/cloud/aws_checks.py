"""
AWS security checks — the pure evaluation layer.

Each check takes the already-collected raw inventory (a plain dict, see aws_collect.collect for the
shape) and returns a list of CloudFinding. No boto3, no network, no DB — so the whole check set is
unit-tested with mocked inventory and needs no AWS credentials.

Two categories: "cspm" (resource misconfiguration — public buckets, lax IAM, open security groups,
weak root account) and "cicd" (CodeBuild/CodePipeline weaknesses — privileged builds, plaintext
secrets). Add a check by writing a function and appending it to CHECKS.
"""

from typing import Callable

from backend.core.cloud.finding import CloudFinding, SENSITIVE_PORTS

# Env-var names that suggest a secret was stored in plaintext instead of Secrets Manager / SSM.
_SECRET_NAME_HINTS = ("secret", "password", "passwd", "token", "api_key", "apikey",
                      "access_key", "private_key", "credential")


# ── CSPM checks ──────────────────────────────────────────────────────────────

def check_s3_public(data: dict) -> list[CloudFinding]:
    out = []
    for b in data.get("s3_buckets", []):
        public = b.get("policy_is_public") or not b.get("public_access_block_all", False)
        if public:
            out.append(CloudFinding(
                "s3_public_bucket",
                f"S3 bucket '{b['name']}' is publicly accessible",
                "high", b["name"],
                "The bucket's policy is public and/or S3 Public Access Block is not fully enabled, "
                "exposing its objects to the internet.",
                "Enable all four S3 Public Access Block settings on the bucket (or account-wide) and "
                "remove public statements from the bucket policy.",
                "s3", "cspm",
            ))
    return out


def check_s3_encryption(data: dict) -> list[CloudFinding]:
    out = []
    for b in data.get("s3_buckets", []):
        if not b.get("encryption_enabled", False):
            out.append(CloudFinding(
                "s3_no_encryption",
                f"S3 bucket '{b['name']}' has no default encryption",
                "medium", b["name"],
                "Objects written to this bucket are not encrypted at rest by default.",
                "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
                "s3", "cspm",
            ))
    return out


def check_iam_mfa(data: dict) -> list[CloudFinding]:
    out = []
    for u in data.get("iam_users", []):
        if u.get("has_console_password") and not u.get("mfa_enabled"):
            out.append(CloudFinding(
                "iam_no_mfa",
                f"IAM user '{u['user_name']}' has console access without MFA",
                "high", u["user_name"],
                "A console-enabled user without MFA is a single stolen password away from account access.",
                "Enforce MFA for all console users (and an IAM policy that denies actions without MFA).",
                "iam", "cspm",
            ))
    return out


def check_iam_stale_keys(data: dict) -> list[CloudFinding]:
    out = []
    for u in data.get("iam_users", []):
        for k in u.get("access_keys", []):
            last_used = k.get("last_used_days")
            if k.get("active") and last_used is not None and last_used > 90:
                out.append(CloudFinding(
                    "iam_stale_key",
                    f"IAM user '{u['user_name']}' has an access key unused for {last_used} days",
                    "medium", f"{u['user_name']}:{k.get('key_id', '?')}",
                    "Long-unused active access keys widen the attack surface for no benefit.",
                    "Rotate or deactivate access keys not used in the last 90 days.",
                    "iam", "cspm",
                ))
    return out


def check_root_access_keys(data: dict) -> list[CloudFinding]:
    root = data.get("root_account") or {}
    if root.get("access_keys_present"):
        return [CloudFinding(
            "root_access_keys",
            "Root account has active access keys",
            "critical", "root",
            "Root account access keys grant unrestricted, unconstrainable access and should never exist.",
            "Delete the root access keys; use IAM roles/users with least privilege instead.",
            "account", "cspm",
        )]
    return []


def check_root_mfa(data: dict) -> list[CloudFinding]:
    root = data.get("root_account") or {}
    if "mfa_enabled" in root and not root.get("mfa_enabled"):
        return [CloudFinding(
            "root_no_mfa",
            "Root account does not have MFA enabled",
            "critical", "root",
            "The root account has full control of the account; without MFA a stolen password is total compromise.",
            "Enable a hardware or virtual MFA device on the root account.",
            "account", "cspm",
        )]
    return []


def check_security_groups(data: dict) -> list[CloudFinding]:
    out = []
    for sg in data.get("security_groups", []):
        for rule in sg.get("open_ingress", []):
            cidr = rule.get("cidr")
            port = rule.get("port")
            if cidr in ("0.0.0.0/0", "::/0") and port in SENSITIVE_PORTS:
                label = SENSITIVE_PORTS[port]
                out.append(CloudFinding(
                    "sg_open_sensitive_port",
                    f"Security group {sg['group_id']} exposes {label} (port {port}) to the internet",
                    "critical" if port in (22, 3389) else "high",
                    f"{sg['group_id']}:{port}",
                    f"Ingress {cidr} → port {port} ({label}) lets anyone on the internet reach this service.",
                    f"Restrict the {label} ingress rule to known IP ranges or a bastion/VPN; never 0.0.0.0/0.",
                    "ec2", "cspm",
                ))
    return out


# ── CI/CD checks ─────────────────────────────────────────────────────────────

def check_codebuild_privileged(data: dict) -> list[CloudFinding]:
    out = []
    for p in data.get("codebuild_projects", []):
        if p.get("privileged_mode"):
            out.append(CloudFinding(
                "codebuild_privileged",
                f"CodeBuild project '{p['name']}' runs in privileged mode",
                "high", p["name"],
                "Privileged mode grants the build container access to the Docker daemon — a build "
                "compromise becomes host/root access on the build fleet.",
                "Disable privileged mode unless building Docker images is required; if so, isolate the project.",
                "codebuild", "cicd",
            ))
    return out


def check_codebuild_plaintext_secrets(data: dict) -> list[CloudFinding]:
    out = []
    for p in data.get("codebuild_projects", []):
        for ev in p.get("env_vars", []):
            name = (ev.get("name") or "").lower()
            if ev.get("type") == "PLAINTEXT" and any(h in name for h in _SECRET_NAME_HINTS):
                out.append(CloudFinding(
                    "codebuild_plaintext_secret",
                    f"CodeBuild project '{p['name']}' stores a secret in plaintext ({ev.get('name')})",
                    "high", f"{p['name']}:{ev.get('name')}",
                    "A secret-looking environment variable is stored as PLAINTEXT, visible to anyone "
                    "who can read the project config or build logs.",
                    "Move the value to Secrets Manager or SSM Parameter Store and reference it by type "
                    "SECRETS_MANAGER / PARAMETER_STORE.",
                    "codebuild", "cicd",
                ))
    return out


CHECKS: list[Callable[[dict], list[CloudFinding]]] = [
    check_s3_public,
    check_s3_encryption,
    check_iam_mfa,
    check_iam_stale_keys,
    check_root_access_keys,
    check_root_mfa,
    check_security_groups,
    check_codebuild_privileged,
    check_codebuild_plaintext_secrets,
]


def evaluate(data: dict) -> list[CloudFinding]:
    """Run every check over the collected inventory and return all findings. A check that raises is
    skipped (a malformed slice of inventory can't suppress the rest of the audit)."""
    findings: list[CloudFinding] = []
    for check in CHECKS:
        try:
            findings.extend(check(data))
        except Exception:
            continue
    return findings
