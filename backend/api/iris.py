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

_IRIS_DIR = Path(__file__).parent.parent.parent / "iris"

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/iris", tags=["iris"])

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
            .single()
            .execute()
        )
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent key")

    if not result.data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent key")

    return result.data


# ── Internal helpers ─────────────────────────────────────────────────────────


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
    asset_id = agent.get("asset_id")
    if not asset_id:
        # Create a transient asset for this agent's hostname so the scan has somewhere to attach
        hostname = agent.get("hostname") or agent.get("name") or agent_id
        # Try to find an existing asset with this host
        existing_asset = (
            db.table("assets")
            .select("id")
            .eq("org_id", org_id)
            .eq("host", hostname)
            .limit(1)
            .execute()
        )
        if existing_asset.data:
            asset_id = existing_asset.data[0]["id"]
        else:
            new_asset = (
                _admin_supabase.table("assets")
                .insert(
                    {
                        "org_id": org_id,
                        "name": agent.get("name") or hostname,
                        "host": hostname,
                        "type": "server",
                        "is_internal": True,
                        "is_active": True,
                        "tags": ["iris"],
                    }
                )
                .execute()
            )
            asset_id = new_asset.data[0]["id"]
            # Link the agent to this new asset for future scans
            _admin_supabase.table("iris_agents").update(
                {"asset_id": asset_id}
            ).eq("id", agent_id).execute()

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
                    "fingerprint": hashlib.sha256(
                        f"{org_id}:{agent_id}:{event['event_type']}:{event['title']}:{event['received_at']}".encode()
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
    except Exception as exc:
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
    """Delete an Iris agent and all its events."""
    rows = (
        _admin_supabase.table("iris_agents")
        .delete()
        .eq("id", agent_id)
        .eq("org_id", user["org_id"])
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

    # Count total pending events for this agent
    pending_count_result = (
        _admin_supabase.table("iris_events")
        .select("id")
        .eq("agent_id", agent["id"])
        .eq("processed", False)
        .execute()
    )
    pending_count = len(pending_count_result.data or [])

    auto_processed = None
    if pending_count > 20:
        try:
            auto_processed = _do_process_agent(agent["id"], org_id, _admin_supabase)
        except Exception as exc:
            logger.warning(
                "iris: auto-process for agent %s failed: %s", agent["id"], exc
            )

    response: dict = {
        "received": len(body.events),
        "pending_after": pending_count,
    }
    if auto_processed:
        response["auto_processed"] = auto_processed

    return response


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
async def get_install_script(
    request: Request,
    api_key: Optional[str] = None,
    agent_id: Optional[str] = None,
):
    """Serve iris/install.sh with server URL and optionally key/agent baked in."""
    script = (_IRIS_DIR / "install.sh").read_text()
    server_url = str(request.base_url).rstrip("/")
    header = f'HORUS_URL="{server_url}"\n'
    if api_key:
        header += f'HORUS_API_KEY="{api_key}"\n'
    if agent_id:
        header += f'HORUS_AGENT_ID="{agent_id}"\n'
    return PlainTextResponse(header + script, media_type="text/x-sh")


@router.get("/package", include_in_schema=False)
async def get_iris_package():
    """Serve the iris/ package as a .tar.gz for the install script to download."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(_IRIS_DIR.rglob("*")):
            if path.suffix == ".pyc" or "__pycache__" in path.parts:
                continue
            tar.add(path, arcname=f"iris/{path.relative_to(_IRIS_DIR)}")
    buf.seek(0)
    return Response(buf.read(), media_type="application/gzip",
                    headers={"Content-Disposition": "attachment; filename=iris.tar.gz"})
