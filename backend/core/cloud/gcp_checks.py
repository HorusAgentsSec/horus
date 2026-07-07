"""
GCP security checks — the pure evaluation layer.

Mirror of aws_checks for Google Cloud: each check takes the collected inventory (see
gcp_collect.collect) and returns CloudFinding objects with provider="gcp". No SDK, no network, no
DB, so the whole set is unit-tested with mocked inventory and needs no GCP credentials.

CSPM: public buckets, legacy bucket ACLs, user-managed service-account keys, primitive
owner/editor roles granted to humans, firewalls open to the internet on sensitive ports, public
Cloud SQL. CI/CD: Cloud Build triggers running as the over-privileged default service account.
"""

from typing import Callable

from backend.core.cloud.finding import CloudFinding, SENSITIVE_PORTS

_PRIMITIVE_ROLES = {"roles/owner": "high", "roles/editor": "medium"}


def _gcp(check_id, title, severity, resource, description, remediation, service, category):
    return CloudFinding(check_id, title, severity, resource, description, remediation,
                        service, category, provider="gcp")


# ── CSPM checks ──────────────────────────────────────────────────────────────

def check_storage_public(data: dict) -> list[CloudFinding]:
    out = []
    for b in data.get("storage_buckets", []):
        if b.get("public"):
            out.append(_gcp(
                "gcs_public_bucket",
                f"Cloud Storage bucket '{b['name']}' is publicly accessible",
                "high", b["name"],
                "An IAM binding grants allUsers or allAuthenticatedUsers access, exposing objects to the internet.",
                "Remove allUsers / allAuthenticatedUsers from the bucket's IAM policy.",
                "storage", "cspm",
            ))
    return out


def check_storage_uniform_access(data: dict) -> list[CloudFinding]:
    out = []
    for b in data.get("storage_buckets", []):
        if not b.get("uniform_bucket_level_access", False):
            out.append(_gcp(
                "gcs_no_uniform_access",
                f"Cloud Storage bucket '{b['name']}' allows legacy object ACLs",
                "low", b["name"],
                "Without uniform bucket-level access, per-object ACLs can grant access that bypasses IAM.",
                "Enable uniform bucket-level access on the bucket.",
                "storage", "cspm",
            ))
    return out


def check_sa_user_managed_keys(data: dict) -> list[CloudFinding]:
    out = []
    for sa in data.get("service_accounts", []):
        n = sa.get("user_managed_key_count", 0)
        if n > 0:
            out.append(_gcp(
                "sa_user_managed_keys",
                f"Service account '{sa['email']}' has {n} user-managed key(s)",
                "medium", sa["email"],
                "User-managed service-account keys don't rotate automatically and are a common leak vector.",
                "Delete user-managed keys; use workload identity or short-lived credentials instead.",
                "iam", "cspm",
            ))
    return out


def check_primitive_roles(data: dict) -> list[CloudFinding]:
    out = []
    for binding in data.get("iam_bindings", []):
        role = binding.get("role")
        if role in _PRIMITIVE_ROLES:
            humans = [m for m in binding.get("members", []) if m.startswith(("user:", "group:"))]
            if humans:
                out.append(_gcp(
                    "iam_primitive_role",
                    f"Primitive role {role} granted to {len(humans)} human member(s)",
                    _PRIMITIVE_ROLES[role], role,
                    f"Primitive roles ({role}) are coarse and over-privileged: {', '.join(humans[:5])}.",
                    "Replace primitive roles with least-privilege predefined or custom roles.",
                    "iam", "cspm",
                ))
    return out


def check_firewall_open(data: dict) -> list[CloudFinding]:
    out = []
    for fw in data.get("firewall_rules", []):
        for rule in fw.get("open_ingress", []):
            cidr, port = rule.get("cidr"), rule.get("port")
            if cidr in ("0.0.0.0/0", "::/0") and port in SENSITIVE_PORTS:
                label = SENSITIVE_PORTS[port]
                out.append(_gcp(
                    "firewall_open_sensitive_port",
                    f"Firewall '{fw['name']}' exposes {label} (port {port}) to the internet",
                    "critical" if port in (22, 3389) else "high",
                    f"{fw['name']}:{port}",
                    f"Ingress {cidr} → port {port} ({label}) lets anyone on the internet reach this service.",
                    f"Restrict the {label} source range to known IPs or use IAP; never 0.0.0.0/0.",
                    "compute", "cspm",
                ))
    return out


def check_sql_public(data: dict) -> list[CloudFinding]:
    out = []
    for inst in data.get("sql_instances", []):
        nets = inst.get("authorized_networks", [])
        if inst.get("public_ip") and any(n in ("0.0.0.0/0", "::/0") for n in nets):
            out.append(_gcp(
                "cloudsql_public",
                f"Cloud SQL instance '{inst['name']}' is open to the internet",
                "high", inst["name"],
                "The instance has a public IP and an authorized network of 0.0.0.0/0 — reachable by anyone.",
                "Remove the 0.0.0.0/0 authorized network; use Private IP or the Cloud SQL Auth Proxy.",
                "cloudsql", "cspm",
            ))
    return out


# ── CI/CD checks ─────────────────────────────────────────────────────────────

def check_cloudbuild_default_sa(data: dict) -> list[CloudFinding]:
    out = []
    for t in data.get("cloudbuild_triggers", []):
        if t.get("uses_default_sa"):
            out.append(_gcp(
                "cloudbuild_default_sa",
                f"Cloud Build trigger '{t['name']}' runs as the default service account",
                "medium", t["name"],
                "The default Cloud Build service account holds the broad 'editor' role; a poisoned "
                "build can act across the whole project.",
                "Run the trigger as a dedicated least-privilege service account.",
                "cloudbuild", "cicd",
            ))
    return out


CHECKS: list[Callable[[dict], list[CloudFinding]]] = [
    check_storage_public,
    check_storage_uniform_access,
    check_sa_user_managed_keys,
    check_primitive_roles,
    check_firewall_open,
    check_sql_public,
    check_cloudbuild_default_sa,
]


def evaluate(data: dict) -> list[CloudFinding]:
    """Run every GCP check over the collected inventory. A check that raises is skipped."""
    findings: list[CloudFinding] = []
    for check in CHECKS:
        try:
            findings.extend(check(data))
        except Exception:
            continue
    return findings
