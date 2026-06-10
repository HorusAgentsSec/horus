"""Case Management — group related findings into incidents with owner + SLA.

Incidents cluster findings under one owner, track a status lifecycle and SLA
deadline, and carry an append-only activity log (notes). Everything is org-scoped:
Bearer-token users get RLS enforcement via the authed client, and we additionally
filter by org_id so API-key (admin client) callers stay inside their tenant too.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.api.deps import require_role
from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["incidents"])

VALID_STATUS = ("open", "in_progress", "resolved", "closed")
VALID_SEVERITY = ("critical", "high", "medium", "low")


# ── Schemas ──────────────────────────────────────────────────────────────────
class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: Optional[str] = None
    severity: str = "medium"
    assignee_id: Optional[str] = None
    sla_deadline: Optional[str] = None  # ISO 8601 timestamp
    finding_ids: List[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=300)
    status: Optional[str] = None
    severity: Optional[str] = None
    assignee_id: Optional[str] = None
    sla_deadline: Optional[str] = None


class LinkFindings(BaseModel):
    finding_ids: List[str]


class NoteCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=10000)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _user_directory(org_id: str) -> dict[str, dict]:
    """Map user_id -> {name, email} for everyone in the org.

    Used to enrich assignee_id / author_id / created_by into something the UI can
    render (initials, names) without leaking IDs from other orgs.
    """
    profiles = (
        supabase.table("profiles")
        .select("id, full_name")
        .eq("org_id", org_id)
        .execute()
        .data
        or []
    )
    try:
        auth_users = supabase.auth.admin.list_users()
        email_map = {u.id: u.email for u in auth_users}
    except Exception:  # best-effort enrichment; never fail the request on this
        email_map = {}
    return {
        p["id"]: {"name": p.get("full_name"), "email": email_map.get(p["id"])}
        for p in profiles
    }


def _person(directory: dict[str, dict], user_id: Optional[str]) -> Optional[dict]:
    if not user_id:
        return None
    info = directory.get(user_id, {})
    return {"id": user_id, "name": info.get("name"), "email": info.get("email")}


def _load_incident(db: Client, incident_id: str, org_id: str) -> dict:
    row = (
        db.table("incidents")
        .select("*")
        .eq("id", incident_id)
        .eq("org_id", org_id)
        .execute()
        .data
    )
    if not row:
        raise HTTPException(404, "incident not found")
    return row[0]


# ── List ─────────────────────────────────────────────────────────────────────
@router.get("")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee_id: Optional[str] = None,
    page: int = 1,
    per_page: int = 25,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    offset = (page - 1) * per_page

    query = db.table("incidents").select("*", count="exact").eq("org_id", org_id)
    if status:
        query = query.eq("status", status)
    if severity:
        query = query.eq("severity", severity)
    if assignee_id:
        query = query.eq("assignee_id", assignee_id)

    result = (
        query.order("created_at", desc=True)
        .range(offset, offset + per_page - 1)
        .execute()
    )
    items = result.data or []

    # Count linked findings per incident in one round-trip, then fold in.
    incident_ids = [i["id"] for i in items]
    counts: dict[str, int] = {}
    if incident_ids:
        links = (
            db.table("incident_findings")
            .select("incident_id")
            .in_("incident_id", incident_ids)
            .execute()
            .data
            or []
        )
        for link in links:
            counts[link["incident_id"]] = counts.get(link["incident_id"], 0) + 1

    directory = _user_directory(org_id)
    for i in items:
        i["finding_count"] = counts.get(i["id"], 0)
        i["assignee"] = _person(directory, i.get("assignee_id"))

    return {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total": result.count or 0,
    }


# ── Create ───────────────────────────────────────────────────────────────────
@router.post("", status_code=201)
async def create_incident(
    body: IncidentCreate,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    if body.severity not in VALID_SEVERITY:
        raise HTTPException(400, f"severity must be one of {VALID_SEVERITY}")

    org_id = user["org_id"]
    payload = {
        "org_id": org_id,
        "title": body.title,
        "description": body.description,
        "severity": body.severity,
        "assignee_id": body.assignee_id,
        "sla_deadline": body.sla_deadline,
        "created_by": user["id"],
    }
    incident = db.table("incidents").insert(payload).execute().data[0]

    # Optionally link findings at creation time — only ones owned by this org.
    if body.finding_ids:
        _link_findings(db, incident["id"], org_id, body.finding_ids)

    incident["finding_count"] = len(_owned_finding_ids(db, org_id, body.finding_ids))
    directory = _user_directory(org_id)
    incident["assignee"] = _person(directory, incident.get("assignee_id"))
    return incident


# ── Detail ───────────────────────────────────────────────────────────────────
@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    incident = _load_incident(db, incident_id, org_id)

    # Linked findings, enriched with title/severity/status from the findings table.
    links = (
        db.table("incident_findings")
        .select("finding_id, added_at, findings(id, title, severity, status)")
        .eq("incident_id", incident_id)
        .order("added_at", desc=True)
        .execute()
        .data
        or []
    )
    findings = []
    for link in links:
        f = link.get("findings")
        if not f:  # finding was deleted but join row lingered — skip defensively
            continue
        findings.append(
            {
                "id": f["id"],
                "title": f.get("title"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "added_at": link.get("added_at"),
            }
        )

    notes = (
        db.table("incident_notes")
        .select("*")
        .eq("incident_id", incident_id)
        .order("created_at", desc=False)
        .execute()
        .data
        or []
    )

    directory = _user_directory(org_id)
    incident["assignee"] = _person(directory, incident.get("assignee_id"))
    incident["created_by_user"] = _person(directory, incident.get("created_by"))
    incident["findings"] = findings
    incident["finding_count"] = len(findings)
    incident["notes"] = [
        {**n, "author": _person(directory, n.get("author_id"))} for n in notes
    ]
    return incident


# ── Update ───────────────────────────────────────────────────────────────────
@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    _load_incident(db, incident_id, org_id)  # 404 if not in org

    updates: dict = {}
    if body.title is not None:
        updates["title"] = body.title
    if body.status is not None:
        if body.status not in VALID_STATUS:
            raise HTTPException(400, f"status must be one of {VALID_STATUS}")
        updates["status"] = body.status
        # Stamp closed_at when entering a terminal state, clear it on re-open.
        if body.status == "closed":
            updates["closed_at"] = datetime.now(timezone.utc).isoformat()
        else:
            updates["closed_at"] = None
    if body.severity is not None:
        if body.severity not in VALID_SEVERITY:
            raise HTTPException(400, f"severity must be one of {VALID_SEVERITY}")
        updates["severity"] = body.severity
    if body.assignee_id is not None:
        updates["assignee_id"] = body.assignee_id or None
    if body.sla_deadline is not None:
        updates["sla_deadline"] = body.sla_deadline or None

    if not updates:
        raise HTTPException(400, "no fields to update")

    rows = (
        db.table("incidents")
        .update(updates)
        .eq("id", incident_id)
        .eq("org_id", org_id)
        .execute()
        .data
    )
    incident = rows[0]
    directory = _user_directory(org_id)
    incident["assignee"] = _person(directory, incident.get("assignee_id"))
    return incident


# ── Soft close (admin) ───────────────────────────────────────────────────────
@router.delete("/{incident_id}", status_code=200)
async def close_incident(
    incident_id: str,
    user=Depends(require_role("admin")),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    _load_incident(db, incident_id, org_id)
    rows = (
        db.table("incidents")
        .update(
            {"status": "closed", "closed_at": datetime.now(timezone.utc).isoformat()}
        )
        .eq("id", incident_id)
        .eq("org_id", org_id)
        .execute()
        .data
    )
    return rows[0]


# ── Link / unlink findings ───────────────────────────────────────────────────
@router.post("/{incident_id}/findings", status_code=200)
async def add_findings(
    incident_id: str,
    body: LinkFindings,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    _load_incident(db, incident_id, org_id)
    linked = _link_findings(db, incident_id, org_id, body.finding_ids)
    return {"linked": linked}


@router.delete("/{incident_id}/findings/{finding_id}", status_code=204)
async def remove_finding(
    incident_id: str,
    finding_id: str,
    user=Depends(require_role("analyst")),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    _load_incident(db, incident_id, org_id)
    db.table("incident_findings").delete().eq("incident_id", incident_id).eq(
        "finding_id", finding_id
    ).execute()


# ── Notes ────────────────────────────────────────────────────────────────────
@router.post("/{incident_id}/notes", status_code=201)
async def add_note(
    incident_id: str,
    body: NoteCreate,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    org_id = user["org_id"]
    _load_incident(db, incident_id, org_id)
    note = (
        db.table("incident_notes")
        .insert(
            {
                "incident_id": incident_id,
                "author_id": user["id"],
                "body": body.body,
            }
        )
        .execute()
        .data[0]
    )
    directory = _user_directory(org_id)
    note["author"] = _person(directory, note.get("author_id"))
    return note


# ── Internal link helpers ────────────────────────────────────────────────────
def _owned_finding_ids(db: Client, org_id: str, finding_ids: List[str]) -> List[str]:
    """Filter the given finding IDs down to those actually owned by this org."""
    if not finding_ids:
        return []
    rows = (
        db.table("findings")
        .select("id")
        .eq("org_id", org_id)
        .in_("id", finding_ids)
        .execute()
        .data
        or []
    )
    return [r["id"] for r in rows]


def _link_findings(
    db: Client, incident_id: str, org_id: str, finding_ids: List[str]
) -> int:
    """Link only org-owned findings; ignore duplicates and foreign IDs."""
    owned = _owned_finding_ids(db, org_id, finding_ids)
    if not owned:
        return 0
    rows = [{"incident_id": incident_id, "finding_id": fid} for fid in owned]
    # upsert so re-linking an already-linked finding is idempotent (PK conflict).
    db.table("incident_findings").upsert(
        rows, on_conflict="incident_id,finding_id"
    ).execute()
    return len(owned)
