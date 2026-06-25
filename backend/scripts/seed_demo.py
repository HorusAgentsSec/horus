"""Siembra la org demo (read-only) que la landing enlaza con ?demo=1.

Crea/reusa el usuario demo, su org y datos ficticios realistas (assets, un scan,
findings con CVEs reales y 30 días de posture snapshots). Idempotente: borra los
datos demo previos de la org y los reinserta.

Uso (desde la raíz del repo):
    backend/.venv/bin/python backend/scripts/seed_demo.py

Lee SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY del entorno o del .env de la raíz.
El service role salta RLS, así que inserta con org_id directamente.
"""
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from supabase import create_client

DEMO_EMAIL = "demo@horusagents.com"
DEMO_PASSWORD = "HorusDemo2026!"  # ponytail: credencial pública de demo, va embebida en el frontend
ORG_NAME = "AcmeCorp Security"


def _load_env() -> tuple[str, str]:
    env = Path(__file__).resolve().parents[2] / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    return url, key


def _get_or_create_user(sb) -> str:
    """Devuelve el id del usuario demo, creándolo si hace falta."""
    try:
        res = sb.auth.admin.create_user(
            {"email": DEMO_EMAIL, "password": DEMO_PASSWORD, "email_confirm": True}
        )
        return res.user.id
    except Exception:
        # Ya existe: lo busco paginando la lista de usuarios.
        page = 1
        while True:
            users = sb.auth.admin.list_users(page=page, per_page=200)
            if not users:
                raise RuntimeError(f"usuario {DEMO_EMAIL} no encontrado")
            for u in users:
                if (u.email or "").lower() == DEMO_EMAIL:
                    # Reafirma la contraseña por si cambió.
                    sb.auth.admin.update_user_by_id(u.id, {"password": DEMO_PASSWORD})
                    return u.id
            page += 1


def main() -> None:
    url, key = _load_env()
    sb = create_client(url, key)

    user_id = _get_or_create_user(sb)

    # Org: reusa por nombre o crea.
    found = sb.table("organizations").select("id").eq("name", ORG_NAME).execute()
    if found.data:
        org_id = found.data[0]["id"]
    else:
        org_id = sb.table("organizations").insert({"name": ORG_NAME}).execute().data[0]["id"]

    # Profile demo como viewer (read-only lo impone require_role en el backend).
    sb.table("profiles").upsert(
        {"id": user_id, "org_id": org_id, "role": "viewer", "full_name": "Demo (read-only)"}
    ).execute()

    # Limpia datos demo previos (orden: hijos antes que padres).
    for table in ("posture_snapshots", "findings", "scans", "assets"):
        sb.table(table).delete().eq("org_id", org_id).execute()

    now = datetime.now(timezone.utc)

    assets = [
        {"name": "Marketing site", "host": "www.acme-demo.com", "type": "web", "tags": ["public", "prod"]},
        {"name": "Customer API", "host": "api.acme-demo.com", "port": 443, "type": "api", "tags": ["prod"]},
        {"name": "Auth service", "host": "auth.acme-demo.com", "type": "web", "tags": ["prod", "critical"]},
        {"name": "Internal Jenkins", "host": "10.0.4.21", "port": 8080, "type": "ip", "is_internal": True, "tags": ["ci"]},
        {"name": "Legacy ActiveMQ", "host": "10.0.4.55", "port": 61616, "type": "ip", "is_internal": True, "tags": ["legacy"]},
        {"name": "Corp domain", "host": "acme-demo.com", "type": "domain", "tags": ["prod"]},
    ]
    for a in assets:
        a["org_id"] = org_id
    asset_rows = sb.table("assets").insert(assets).execute().data
    by_host = {a["host"]: a["id"] for a in asset_rows}

    scan = sb.table("scans").insert({
        "org_id": org_id,
        "asset_id": by_host["api.acme-demo.com"],
        "status": "completed",
        "tools_used": ["nuclei", "nmap"],
        "triggered_by": "manual",
        "started_at": (now - timedelta(hours=2)).isoformat(),
        "completed_at": (now - timedelta(hours=2, minutes=-6)).isoformat(),
    }).execute().data[0]
    scan_id = scan["id"]

    # severity, title, cve, cvss, host, status, kev(activamente explotado)
    findings = [
        ("critical", "Apache Log4j2 RCE (Log4Shell)", ["CVE-2021-44228"], 10.0, "api.acme-demo.com", "open", True),
        ("critical", "Spring Framework RCE (Spring4Shell)", ["CVE-2022-22965"], 9.8, "auth.acme-demo.com", "open", True),
        ("critical", "Apache ActiveMQ RCE", ["CVE-2023-46604"], 10.0, "10.0.4.55", "in_progress", True),
        ("high", "Jenkins arbitrary file read", ["CVE-2024-23897"], 7.5, "10.0.4.21", "open", False),
        ("high", "TLS: weak ciphers enabled", [], 7.4, "www.acme-demo.com", "open", False),
        ("high", "Exposed .git directory", [], 7.5, "www.acme-demo.com", "open", False),
        ("medium", "Missing security headers (CSP, HSTS)", [], 5.3, "www.acme-demo.com", "open", False),
        ("medium", "Cookie without Secure/HttpOnly", [], 5.0, "auth.acme-demo.com", "resolved", False),
        ("low", "Server version disclosure", [], 3.7, "api.acme-demo.com", "open", False),
        ("info", "robots.txt exposes admin path", [], 0.0, "www.acme-demo.com", "open", False),
    ]
    finding_rows = []
    for i, (sev, title, cves, cvss, host, status, kev) in enumerate(findings):
        finding_rows.append({
            "org_id": org_id,
            "scan_id": scan_id,
            "asset_id": by_host[host],
            "title": title,
            "description": f"Detected on {host} during automated scan.",
            "severity": sev,
            "cvss_score": cvss,
            "cve_ids": cves,
            "status": status,
            "fingerprint": f"demo-{i}-{title[:20]}",
            "raw_data": {"kev": kev, "demo": True},
            "first_seen_at": (now - timedelta(days=12 - i)).isoformat(),
            "last_seen_at": now.isoformat(),
        })
    sb.table("findings").insert(finding_rows).execute()

    # 30 días de posture: el riesgo baja según se resuelven cosas (arco narrativo).
    snaps = []
    for d in range(29, -1, -1):
        day = date.today() - timedelta(days=d)
        # Empieza alto (~180) y baja hacia ~120 con dientes de sierra suaves.
        risk = 120 + int((d / 29) * 60) + (5 if d % 7 == 0 else 0)
        crit = 3 if d > 4 else 3
        high = 3 if d > 10 else 3
        snaps.append({
            "org_id": org_id, "snapshot_date": day.isoformat(), "risk_score": risk,
            "open_findings": 9, "kev_active": 3 if d > 3 else 2,
            "critical": crit, "high": high, "medium": 2, "low": 1, "info": 1,
        })
    sb.table("posture_snapshots").upsert(snaps, on_conflict="org_id,snapshot_date").execute()

    print(f"OK demo: org={org_id} user={DEMO_EMAIL} assets={len(asset_rows)} findings={len(finding_rows)}")


if __name__ == "__main__":
    main()
