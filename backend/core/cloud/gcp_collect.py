"""
GCP inventory collection — the effectful layer (Google APIs).

Reads a read-only snapshot of a project via the google-api-python-client discovery API and returns
the plain-dict inventory that gcp_checks evaluates. Kept separate from the checks so the checks stay
pure/testable and credentials only ever touch this module. Every per-service call is wrapped so one
denied API doesn't abort the whole audit.

Credentials come from a service-account JSON key stored in the integration config. The Google libs
are optional dependencies — imported lazily so the rest of the app runs without them installed.
"""

import json
import logging

logger = logging.getLogger(__name__)

_READONLY_SCOPE = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


def build_credentials(config: dict):
    """Build read-only service-account credentials from the integration config."""
    from google.oauth2 import service_account

    info = config.get("service_account_json")
    if isinstance(info, str):
        info = json.loads(info)
    return service_account.Credentials.from_service_account_info(info, scopes=_READONLY_SCOPE)


def collect(config: dict) -> dict:
    """Collect the read-only inventory the checks need. Best-effort per service."""
    from googleapiclient import discovery

    creds = build_credentials(config)
    project_id = config.get("project_id") or getattr(creds, "project_id", None) or "unknown"

    def client(name, version):
        return discovery.build(name, version, credentials=creds, cache_discovery=False)

    return {
        "project_id": project_id,
        "storage_buckets": _collect_storage(client, project_id),
        "service_accounts": _collect_service_accounts(client, project_id),
        "iam_bindings": _collect_iam_bindings(client, project_id),
        "firewall_rules": _collect_firewalls(client, project_id),
        "sql_instances": _collect_sql(client, project_id),
        "cloudbuild_triggers": _collect_cloudbuild(client, project_id),
    }


def _collect_storage(client, project_id: str) -> list[dict]:
    out = []
    try:
        storage = client("storage", "v1")
        buckets = storage.buckets().list(project=project_id).execute().get("items", [])
    except Exception as e:
        logger.warning("GCP collect: storage list failed: %s", e)
        return out
    for b in buckets:
        name = b["name"]
        out.append({
            "name": name,
            "public": _bucket_public(storage, name),
            "uniform_bucket_level_access": b.get("iamConfiguration", {})
                .get("uniformBucketLevelAccess", {}).get("enabled", False),
        })
    return out


def _bucket_public(storage, name: str) -> bool:
    try:
        policy = storage.buckets().getIamPolicy(bucket=name).execute()
        members = {m for b in policy.get("bindings", []) for m in b.get("members", [])}
        return bool(members & {"allUsers", "allAuthenticatedUsers"})
    except Exception:
        return False


def _collect_service_accounts(client, project_id: str) -> list[dict]:
    out = []
    try:
        iam = client("iam", "v1")
        sas = iam.projects().serviceAccounts().list(
            name=f"projects/{project_id}").execute().get("accounts", [])
    except Exception as e:
        logger.warning("GCP collect: service accounts list failed: %s", e)
        return out
    for sa in sas:
        out.append({
            "email": sa["email"],
            "user_managed_key_count": _sa_user_keys(iam, sa["name"]),
        })
    return out


def _sa_user_keys(iam, sa_name: str) -> int:
    try:
        keys = iam.projects().serviceAccounts().keys().list(
            name=sa_name, keyTypes=["USER_MANAGED"]).execute().get("keys", [])
        return len(keys)
    except Exception:
        return 0


def _collect_iam_bindings(client, project_id: str) -> list[dict]:
    try:
        crm = client("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        return [{"role": b.get("role"), "members": b.get("members", [])}
                for b in policy.get("bindings", [])]
    except Exception as e:
        logger.warning("GCP collect: getIamPolicy failed: %s", e)
        return []


def _collect_firewalls(client, project_id: str) -> list[dict]:
    out = []
    try:
        compute = client("compute", "v1")
        rules = compute.firewalls().list(project=project_id).execute().get("items", [])
    except Exception as e:
        logger.warning("GCP collect: firewalls list failed: %s", e)
        return out
    for fw in rules:
        if fw.get("direction", "INGRESS") != "INGRESS" or fw.get("disabled"):
            continue
        cidrs = fw.get("sourceRanges", [])
        open_ingress = []
        for allowed in fw.get("allowed", []):
            for port_spec in allowed.get("ports", []):
                for port in _expand_ports(port_spec):
                    for cidr in cidrs:
                        open_ingress.append({"port": port, "cidr": cidr,
                                             "protocol": allowed.get("IPProtocol")})
        out.append({"name": fw.get("name"), "open_ingress": open_ingress})
    return out


def _expand_ports(spec: str) -> list[int]:
    """GCP ports are strings: '22' or '8000-8100'. Cap ranges so an absurd span can't explode."""
    try:
        if "-" in spec:
            lo, hi = (int(x) for x in spec.split("-", 1))
            return list(range(lo, min(hi, lo + 1000) + 1))
        return [int(spec)]
    except ValueError:
        return []


def _collect_sql(client, project_id: str) -> list[dict]:
    out = []
    try:
        sql = client("sqladmin", "v1beta4")
        instances = sql.instances().list(project=project_id).execute().get("items", [])
    except Exception as e:
        logger.warning("GCP collect: sql list failed: %s", e)
        return out
    for inst in instances:
        ip_cfg = inst.get("settings", {}).get("ipConfiguration", {})
        out.append({
            "name": inst.get("name"),
            "public_ip": ip_cfg.get("ipv4Enabled", False),
            "authorized_networks": [n.get("value") for n in ip_cfg.get("authorizedNetworks", [])],
        })
    return out


def collect_audit_logs(config: dict, lookback_hours: int = 24, max_events: int = 2000) -> list[dict]:
    """Recent admin-activity audit log entries, normalized for gcp_auditlog.classify_event.

    Bounded by a time window and a hard event cap. Best-effort: any failure returns an empty list."""
    from datetime import datetime, timedelta, timezone
    from googleapiclient import discovery

    out: list[dict] = []
    try:
        creds = build_credentials(config)
        project_id = config.get("project_id") or getattr(creds, "project_id", None)
        logging_svc = discovery.build("logging", "v2", credentials=creds, cache_discovery=False)
        start = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        log_filter = (
            'logName:"cloudaudit.googleapis.com%2Factivity" '
            f'AND timestamp>="{start}"'
        )
        body = {"resourceNames": [f"projects/{project_id}"], "filter": log_filter,
                "orderBy": "timestamp desc", "pageSize": 500}
        req = logging_svc.entries().list(body=body)
        while req is not None and len(out) < max_events:
            resp = req.execute()
            for entry in resp.get("entries", []):
                proto = entry.get("protoPayload", {})
                out.append({
                    "method_name": proto.get("methodName"),
                    "principal": (proto.get("authenticationInfo") or {}).get("principalEmail"),
                    "caller_ip": (proto.get("requestMetadata") or {}).get("callerIp"),
                    "timestamp": entry.get("timestamp"),
                    "insert_id": entry.get("insertId"),
                    "request": proto.get("request") or {},
                })
                if len(out) >= max_events:
                    break
            req = logging_svc.entries().list_next(req, resp)
    except Exception as e:
        logger.warning("GCP collect: audit logs list failed: %s", e)
    return out


def _collect_cloudbuild(client, project_id: str) -> list[dict]:
    out = []
    try:
        cb = client("cloudbuild", "v1")
        triggers = cb.projects().triggers().list(projectId=project_id).execute().get("triggers", [])
    except Exception as e:
        logger.warning("GCP collect: cloudbuild triggers list failed: %s", e)
        return out
    for t in triggers:
        # An empty serviceAccount means the build runs as the default Cloud Build SA (broad editor).
        out.append({
            "name": t.get("name") or t.get("id"),
            "uses_default_sa": not t.get("serviceAccount"),
        })
    return out
