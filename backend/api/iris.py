"""
Horus Iris — registered Unix agents and the event pipeline they feed.

Two auth planes:
  • User endpoints (Bearer JWT / hrs_ API key via get_current_user):
      POST   /iris/agents/register          — register a new agent; returns one-time key
      GET    /iris/agents                   — list agents for the org
      DELETE /iris/agents/{agent_id}        — remove an agent and its events
      POST   /iris/agents/{agent_id}/process — batch pending events → scan → pipeline

  • Agent endpoints (X-Iris-Key: irs_... header, no JWT):
      POST   /iris/events                   — daemon reports a batch of events
"""

import hashlib
import io
import logging
import secrets
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.core.executor import submit_scan
from backend.core.supabase_client import supabase as _admin_supabase

# The Rust agent (iris-rs) is the single supported implementation. The legacy Python
# daemon under iris/ is retired; everything the installer needs lives here.
_IRIS_DIR = Path(__file__).parent.parent.parent / "iris-rs"
_IRIS_BINARY = _IRIS_DIR / "target" / "release" / "horus-iris"

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/iris", tags=["iris"])

# The live-triage modal polls every ~12s; each call hits the LLM. Cache per agent so
# many pollers (or one left open) can't burn tokens. {agent_id: (epoch_s, result)}
_AI_ANALYSIS_TTL_S = 30.0
_ai_analysis_cache: dict[str, tuple[float, dict]] = {}

# ── Pydantic models ─────────────────────────────────────────────────────────


class AgentRegisterRequest(BaseModel):
    name: str
    asset_id: Optional[str] = None


class AgentRegisterResponse(BaseModel):
    agent_id: str
    key_prefix: str
    api_key: str  # shown ONCE — irs_<token>


class AgentListItem(BaseModel):
    id: str
    name: str
    hostname: Optional[str]
    platform: Optional[str]
    ip: Optional[str]
    key_prefix: str
    asset_id: Optional[str]
    last_seen_at: Optional[str]
    status: str
    config: dict
    created_at: str
    pending_events: int
    total_events: int


class IrisEventIn(BaseModel):
    event_type: str
    severity: str = "info"
    title: str
    payload: dict


class IrisEventsBatch(BaseModel):
    agent_id: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    events: list[IrisEventIn]


# ── Agent auth helper ────────────────────────────────────────────────────────


def _resolve_iris_key(x_iris_key: str) -> dict:
    """Resolve an irs_... key to the iris_agent row. Raises 401 on failure."""
    if not x_iris_key or not x_iris_key.startswith("irs_"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent key")

    key_hash = hashlib.sha256(x_iris_key.encode()).hexdigest()
    try:
        result = (
            _admin_supabase.table("iris_agents")
            .select("id, org_id, name, hostname, asset_id")
            .eq("api_key_hash", key_hash)
            .is_("deleted_at", "null")
            .single()
            .execute()
        )
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent key")

    if not result.data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent key")

    return result.data


# ── Internal helpers ─────────────────────────────────────────────────────────


def _resolve_or_create_asset(agent: dict, org_id: str) -> str:
    """Return an asset_id for this agent, creating a host asset if it has none.
    findings.asset_id is NOT NULL, so every Iris finding needs a real asset to attach to.
    Uses the service-role client so it works from agent-auth paths and the scheduler."""
    asset_id = agent.get("asset_id")
    if asset_id:
        return asset_id
    hostname = agent.get("hostname") or agent.get("name") or agent["id"]
    existing = (
        _admin_supabase.table("assets")
        .select("id").eq("org_id", org_id).eq("host", hostname).limit(1).execute().data
    )
    if existing:
        asset_id = existing[0]["id"]
    else:
        asset_id = (
            _admin_supabase.table("assets").insert({
                "org_id": org_id, "name": agent.get("name") or hostname, "host": hostname,
                "type": "server", "is_internal": True, "is_active": True, "tags": ["iris"],
            }).execute().data[0]["id"]
        )
    # Link it back so future events/findings reuse it.
    _admin_supabase.table("iris_agents").update({"asset_id": asset_id}).eq("id", agent["id"]).execute()
    return asset_id


# High-confidence deterministic threats: act immediately, don't wait for the LLM triage
# interval. Maps an incoming event to (severity, reason) when it's unambiguous.
def _deterministic_threat(ev: "IrisEventIn") -> Optional[tuple[str, str]]:
    subtype = str((ev.payload or {}).get("subtype", ""))
    if subtype == "agent_tamper":
        return ("critical", "Iris monitoring agent was stopped/disabled; possible defense evasion (MITRE T1562.001)")
    if subtype == "brute_force":
        return ("high", "Brute-force authentication attempt detected")
    if ev.event_type == "new_connection" and ev.severity in ("high", "critical"):
        return ("high", "Outbound connection to a known C2/backdoor port")
    return None


def _alert_deterministic_threats(agent: dict, org_id: str, events: list["IrisEventIn"]) -> None:
    """Create findings + an in-app alert for high-confidence threats, immediately and
    independent of the AI triage interval. Best-effort: never breaks event ingestion."""
    host = agent.get("hostname") or agent.get("name") or agent["id"]
    now = datetime.now(timezone.utc).isoformat()
    created: list[str] = []
    worst = "high"
    asset_id = None  # resolved lazily on the first real threat (avoids creating assets for noise)
    for ev in events:
        verdict = _deterministic_threat(ev)
        if not verdict:
            continue
        severity, reason = verdict
        if severity == "critical":
            worst = "critical"
        if asset_id is None:
            asset_id = _resolve_or_create_asset(agent, org_id)
        fp = hashlib.sha256(
            f"iris_rt:{org_id}:{agent['id']}:{ev.event_type}:{ev.title}".encode()
        ).hexdigest()
        try:
            _admin_supabase.table("findings").insert({
                "org_id": org_id,
                "asset_id": asset_id,
                "title": f"[Iris] {ev.title}",
                "description": reason,
                "severity": severity,
                "status": "open",
                "source": "iris",
                "fingerprint": fp,
                "raw_data": {
                    "tool": "iris", "template_id": f"iris_rt:{ev.event_type}",
                    "host": host, "event_type": ev.event_type, "payload": ev.payload,
                },
                "last_seen_at": now,
            }).execute()
            created.append(ev.title)
        except Exception as exc:
            logger.debug("iris: deterministic finding upsert skipped for %s: %s", ev.title, exc)

    if not created:
        return
    try:
        recipients = (
            _admin_supabase.table("profiles").select("id")
            .eq("org_id", org_id).in_("role", ["admin", "analyst"]).execute().data or []
        )
        if recipients:
            title = f"Iris alert on {host}"
            body = created[0] if len(created) == 1 else f"{len(created)} high-risk events on {host}"
            _admin_supabase.table("notifications").insert([
                {
                    "org_id": org_id, "user_id": r["id"], "type": "iris_alert",
                    "title": title, "body": body,
                    "metadata": {"agent_id": agent["id"], "severity": worst},
                }
                for r in recipients
            ]).execute()
    except Exception:
        logger.exception("iris: in-app alert failed for agent %s", agent["id"])


def _do_process_agent(agent_id: str, org_id: str, db: Client) -> dict:
    # 1. Fetch agent details
    agent_result = (
        db.table("iris_agents")
        .select("id, name, hostname, ip, asset_id, org_id")
        .eq("id", agent_id)
        .eq("org_id", org_id)
        .single()
        .execute()
    )
    if not agent_result.data:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = agent_result.data

    # 2. Fetch pending events
    events_result = (
        db.table("iris_events")
        .select("*")
        .eq("agent_id", agent_id)
        .eq("org_id", org_id)
        .eq("processed", False)
        .order("received_at")
        .execute()
    )
    events = events_result.data or []
    if not events:
        return {"scan_id": None, "events_processed": 0, "message": "No pending events"}

    # 3. Resolve or create an asset for the scan
    asset_id = _resolve_or_create_asset(agent, org_id)

    # 4. Create a scan row
    now = datetime.now(timezone.utc).isoformat()
    scan_result = (
        _admin_supabase.table("scans")
        .insert(
            {
                "org_id": org_id,
                "asset_id": asset_id,
                "status": "pending",
                "tools_used": ["iris"],
                "triggered_by": f"iris:{agent_id}",
            }
        )
        .execute()
    )
    scan_id = scan_result.data[0]["id"]

    # 5. Insert raw findings into the findings table pre-seeded for the pipeline
    event_ids = [e["id"] for e in events]
    host = agent.get("hostname") or agent.get("ip") or agent_id
    for event in events:
        try:
            _admin_supabase.table("findings").insert(
                {
                    "org_id": org_id,
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "title": event["title"],
                    "description": f"[Iris {event['event_type']}] {event['title']}",
                    "severity": event["severity"],
                    "status": "open",
                    "source": "iris",
                    # No received_at: identical recurring events (e.g. a noisy SQLite WAL
                    # rewriting the same path) collapse to one finding instead of stacking.
                    "fingerprint": hashlib.sha256(
                        f"{org_id}:{agent_id}:{event['event_type']}:{event['title']}".encode()
                    ).hexdigest(),
                    "raw_data": {
                        "tool": "iris",
                        "template_id": f"iris:{event['event_type']}",
                        "host": host,
                        "event_type": event["event_type"],
                        "payload": event["payload"],
                    },
                    "last_seen_at": now,
                }
            ).execute()
        except Exception as exc:
            logger.warning("iris: could not insert finding for event %s: %s", event["id"], exc)

    # 6. Mark events processed and link them to the scan
    _admin_supabase.table("iris_events").update(
        {"processed": True, "scan_id": scan_id}
    ).in_("id", event_ids).execute()

    # 7. Submit to the AI pipeline (bounded pool, non-blocking)
    submit_scan(scan_id, org_id)

    return {"scan_id": scan_id, "events_processed": len(events)}


# ── User-authenticated endpoints ─────────────────────────────────────────────


@router.post("/agents/register", response_model=AgentRegisterResponse, status_code=201)
async def register_agent(
    body: AgentRegisterRequest,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Register a new Iris agent. The API key is returned ONCE — store it safely."""
    # Generate: irs_<32 random chars>
    secret = "irs_" + secrets.token_urlsafe(24)[:32]
    key_hash = hashlib.sha256(secret.encode()).hexdigest()
    key_prefix = secret[:12]  # irs_<8 chars>

    row: dict = {
        "org_id": user["org_id"],
        "name": body.name,
        "api_key_hash": key_hash,
        "key_prefix": key_prefix,
        "status": "offline",
        "config": {},
    }
    if body.asset_id:
        # Verify asset belongs to org
        asset = (
            db.table("assets")
            .select("id")
            .eq("id", body.asset_id)
            .eq("org_id", user["org_id"])
            .execute()
        )
        if not asset.data:
            raise HTTPException(status_code=404, detail="Asset not found")
        row["asset_id"] = body.asset_id

    # created_by only makes sense for real users, not API key callers
    if not user.get("is_api_key"):
        row["created_by"] = user["id"]

    try:
        result = _admin_supabase.table("iris_agents").insert(row).execute()
    except Exception:
        raise HTTPException(status_code=500, detail="Could not register agent")

    agent_row = result.data[0]
    return AgentRegisterResponse(
        agent_id=agent_row["id"],
        key_prefix=key_prefix,
        api_key=secret,
    )


@router.get("/agents", response_model=list[AgentListItem])
async def list_agents(
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """List all Iris agents for the org."""
    agents = (
        db.table("iris_agents")
        .select("*")
        .eq("org_id", user["org_id"])
        .order("created_at", desc=True)
        .execute()
        .data
        or []
    )
    if not agents:
        return []

    agent_ids = [a["id"] for a in agents]

    # Count pending events per agent in a single query
    events_rows = (
        db.table("iris_events")
        .select("agent_id")
        .in_("agent_id", agent_ids)
        .eq("processed", False)
        .execute()
        .data
        or []
    )
    pending_by_agent = Counter(e["agent_id"] for e in events_rows)

    # Total events per agent — what the UI shows so a healthy (fully-triaged) agent doesn't
    # read "0". head=True returns just the count, no rows.
    # ponytail: N+1 over agents, but the agent list is small (tens, not thousands).
    # NB: head=True returns count=0 with this supabase-py version, so use a limit(1) probe —
    # it fetches one throwaway row but reports the accurate exact count.
    total_by_agent: dict[str, int] = {}
    for aid in agent_ids:
        try:
            total_by_agent[aid] = (
                db.table("iris_events").select("id", count="exact")
                .eq("agent_id", aid).limit(1).execute().count or 0
            )
        except Exception:
            total_by_agent[aid] = 0

    return [
        AgentListItem(
            id=a["id"],
            name=a["name"],
            hostname=a.get("hostname"),
            platform=a.get("platform"),
            ip=a.get("ip"),
            key_prefix=a["key_prefix"],
            asset_id=a.get("asset_id"),
            last_seen_at=a.get("last_seen_at"),
            status=a.get("status", "offline"),
            config=a.get("config") or {},
            created_at=a["created_at"],
            pending_events=pending_by_agent.get(a["id"], 0),
            total_events=total_by_agent.get(a["id"], 0),
        )
        for a in agents
    ]


@router.get("/agents/{agent_id}/events")
async def list_agent_events(
    agent_id: str,
    limit: int = 50,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Return the most recent events for a specific agent."""
    # Verify the agent belongs to the org before returning events
    agent = (
        db.table("iris_agents")
        .select("id")
        .eq("id", agent_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    events = (
        db.table("iris_events")
        .select("id, event_type, severity, title, payload, received_at")
        .eq("agent_id", agent_id)
        .order("received_at", desc=True)
        .limit(min(limit, 200))
        .execute()
        .data
        or []
    )
    return events


@router.delete("/agents/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: str,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Soft-delete an Iris agent. Its events are preserved and recoverable in the DB."""
    rows = (
        _admin_supabase.table("iris_agents")
        .update({"deleted_at": datetime.now(timezone.utc).isoformat()})
        .eq("id", agent_id)
        .eq("org_id", user["org_id"])
        .is_("deleted_at", "null")
        .execute()
        .data
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Agent not found")


@router.post("/agents/{agent_id}/process", status_code=202)
async def process_agent_events(
    agent_id: str,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """
    Batch all pending events for an agent into a scan and submit it to the AI pipeline.
    Returns immediately; the pipeline runs asynchronously.
    """
    return _do_process_agent(agent_id, user["org_id"], db)


@router.get("/agents/{agent_id}/ai-analysis")
async def agent_ai_analysis(
    agent_id: str,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """
    Live, read-only preview of the Iris AI triage analyst for one agent.

    Gathers the agent's pending events, builds the same summary the scheduled triage
    sends to the LLM, calls the model, and returns the prompt + raw AI response.
    Writes nothing; purely for the UI's live-view modal.
    """
    import time
    from backend.core.iris_triage import analyze_events_readonly
    from backend.core.token_budget import check_budget

    # Verify the agent belongs to the org
    agent = (
        db.table("iris_agents")
        .select("id")
        .eq("id", agent_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Serve a recent cached analysis if fresh — caps LLM calls under rapid polling.
    cached = _ai_analysis_cache.get(agent_id)
    if cached and (time.monotonic() - cached[0]) < _AI_ANALYSIS_TTL_S:
        return cached[1]

    # Don't spend tokens on a read-only preview once the org is over budget.
    budget = check_budget(user["org_id"])
    if not budget["ok"]:
        return {"analyzed": 0, "groups": 0, "prompt": None, "response": None,
                "model": None, "message": f"AI triage paused: token budget exceeded ({budget['period']})."}

    # Recent events regardless of the processed flag: this is a live view of what the
    # agent is seeing. Filtering on processed=False would show nothing once the scheduled
    # triage has cleared the backlog, which is the normal state for a healthy agent.
    rows = (
        db.table("iris_events")
        .select("id, event_type, severity, title, agent_id")
        .eq("agent_id", agent_id)
        .eq("org_id", user["org_id"])
        .order("received_at", desc=True)
        .limit(2000)
        .execute()
        .data
        or []
    )

    try:
        result = analyze_events_readonly(rows)
        _ai_analysis_cache[agent_id] = (time.monotonic(), result)
        return result
    except Exception as exc:
        logger.error("iris ai-analysis failed for agent %s: %s", agent_id, exc)
        raise HTTPException(status_code=502, detail="AI analysis failed")


# ── Agent-authenticated endpoint ─────────────────────────────────────────────


@router.post("/events", status_code=202)
async def receive_events(
    body: IrisEventsBatch,
    x_iris_key: Optional[str] = Header(None),
):
    """
    Daemon endpoint — authenticated via X-Iris-Key header (irs_... key), not JWT.

    Stores each event in iris_events, updates agent heartbeat, and auto-processes
    if there are more than 20 pending events after this batch.
    """
    agent = _resolve_iris_key(x_iris_key or "")

    # Verify the agent_id in the body matches the authenticated agent
    if body.agent_id != agent["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="agent_id does not match authenticated agent",
        )

    org_id = agent["org_id"]
    now = datetime.now(timezone.utc).isoformat()

    # Update heartbeat
    _admin_supabase.table("iris_agents").update(
        {
            "last_seen_at": now,
            "status": "online",
            **({"hostname": body.hostname} if body.hostname else {}),
            **({"ip": body.ip} if body.ip else {}),
        }
    ).eq("id", agent["id"]).execute()

    # Insert events (remap unknown event_types to avoid DB check-constraint violations)
    _VALID_EVENT_TYPES = {
        "file_change", "new_process", "new_listener",
        "new_connection", "auth_event", "log_anomaly",
    }
    if body.events:
        rows = [
            {
                "agent_id": agent["id"],
                "org_id": org_id,
                "event_type": ev.event_type if ev.event_type in _VALID_EVENT_TYPES else "new_process",
                "severity": ev.severity,
                "title": ev.title,
                "payload": ev.payload,
            }
            for ev in body.events
        ]
        try:
            _admin_supabase.table("iris_events").insert(rows).execute()
        except Exception as exc:
            logger.error("iris: failed to insert event batch for agent %s: %s", agent["id"], exc)

    # Routine noise waits for the scheduled LLM triage. But high-confidence deterministic
    # threats (agent tamper, brute-force, C2 ports) alert immediately — waiting up to an hour
    # to flag that the agent itself was just disabled defeats the point of monitoring.
    try:
        _alert_deterministic_threats(agent, org_id, body.events)
    except Exception:
        logger.exception("iris: deterministic threat alerting failed for agent %s", agent["id"])

    return {"received": len(body.events)}


# ── Agent ping (key validation, no JWT) ─────────────────────────────────────


@router.get("/ping")
async def ping(x_iris_key: Optional[str] = Header(None)):
    """Daemon uses this to verify key validity and server reachability."""
    agent = _resolve_iris_key(x_iris_key or "")
    return {"ok": True, "agent": agent["name"], "agent_id": agent["id"]}


# ── Public install endpoints (no auth) ──────────────────────────────────────


@router.get("/uninstall.sh", response_class=PlainTextResponse, include_in_schema=False)
async def get_uninstall_script():
    return PlainTextResponse((_IRIS_DIR / "uninstall.sh").read_text(), media_type="text/x-sh")


@router.get("/install.sh", response_class=PlainTextResponse, include_in_schema=False)
async def get_install_script(request: Request):
    """Serve the Rust agent installer with the server URL baked in.

    The API key is NOT accepted as a query param (it would land in server access logs).
    The dashboard passes it on the client command line via env (HORUS_API_KEY), the same
    pattern agent installers like Datadog use.
    """
    script = (_IRIS_DIR / "install.sh").read_text()
    server_url = str(request.base_url).rstrip("/")
    header = f'HORUS_URL="${{HORUS_URL:-{server_url}}}"\n'
    return PlainTextResponse(header + script, media_type="text/x-sh")


@router.get("/binary", include_in_schema=False)
async def get_iris_binary():
    """Serve the compiled Rust agent binary the installer downloads.

    Built at deploy time (`cd iris-rs && cargo build --release`). If it isn't there yet,
    return 503 with the build step rather than a confusing download error — the installer
    can also build from source via the /package fallback.
    """
    if not _IRIS_BINARY.exists():
        raise HTTPException(
            status_code=503,
            detail="Agent binary not built. On the server run: cd iris-rs && cargo build --release",
        )
    return Response(
        _IRIS_BINARY.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=horus-iris"},
    )


@router.get("/package", include_in_schema=False)
async def get_iris_package():
    """Serve the iris-rs source as a .tar.gz (build-from-source fallback). Excludes build
    artifacts and VCS noise so the download stays small."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(_IRIS_DIR.rglob("*")):
            parts = path.parts
            if "target" in parts or ".git" in parts or path.suffix == ".pyc":
                continue
            tar.add(path, arcname=f"iris-rs/{path.relative_to(_IRIS_DIR)}")
    buf.seek(0)
    return Response(buf.read(), media_type="application/gzip",
                    headers={"Content-Disposition": "attachment; filename=iris-rs.tar.gz"})
