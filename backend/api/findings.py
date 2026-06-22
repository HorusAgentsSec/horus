import logging
import json
import csv
from io import StringIO
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db
from backend.core import verdict_memory
from backend.core.noise import is_absence_finding
from backend.models.schemas import FindingStatusUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@router.get("")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    tool: Optional[str] = None,
    order_by: Optional[str] = None,
    include_noise: bool = False,
    page: int = 1,
    per_page: int = 50,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    def apply_filters(query):
        if severity:
            query = query.eq("severity", severity)
        if status:
            query = query.eq("status", status)
        if asset_id:
            query = query.eq("asset_id", asset_id)
        if cve_id:
            query = query.contains("cve_ids", [cve_id])
        if tool:
            query = query.eq("raw_data->>tool", tool)
        return query

    offset = (page - 1) * per_page
    # API keys use admin client; must manually filter by org_id
    base_query = db.table("findings").select("*, assets(name, host)")
    if user.get("is_api_key"):
        query = base_query.eq("org_id", user["org_id"])
    else:
        # Bearer token users: RLS handles org_id via current_org_id()
        query = base_query.eq("org_id", user["org_id"])

    query = apply_filters(query)
    # Absence/scanner-noise findings ("No DOM-based XSS found…") are hidden by default so the
    # list shows real signal; include_noise=true reveals them (UI "N hidden — Show" banner).
    if not include_noise:
        query = query.eq("is_noise", False)

    if order_by == "severity":
        # severity_rank is a generated column (0=critical … 4=info); ordering by the
        # text column sorts alphabetically (critical, high, info, low, medium), which
        # is not risk order. See migration 20260622_findings_severity_rank.
        query = query.order("severity_rank", desc=False).order("created_at", desc=True)
    else:
        # default and fallback (epss/ssvc are inside jsonb, order by created_at)
        query = query.order("created_at", desc=True)

    result = query.range(offset, offset + per_page - 1).execute()

    # How many noise findings match the same filters, so the UI can say "N hidden".
    noise_count = (
        apply_filters(
            db.table("findings").select("id", count="exact").eq("org_id", user["org_id"])
        )
        .eq("is_noise", True)
        .execute()
        .count
        or 0
    )
    return {"items": result.data, "noise_count": noise_count}


@router.get("/export")
async def export_findings(
    format: str = "jsonl",
    include_noise: bool = False,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Stream findings in JSONL or CSV format for SIEM integration."""
    if format not in ("jsonl", "csv"):
        raise HTTPException(status_code=400, detail="format must be 'jsonl' or 'csv'")

    query = db.table("findings").select("*, assets(name, host)").eq("org_id", user["org_id"])
    if not include_noise:
        query = query.eq("is_noise", False)

    findings = query.order("created_at", desc=True).execute().data or []

    def generate():
        if format == "jsonl":
            for f in findings:
                row = _export_row(f)
                yield json.dumps(row) + "\n"
        else:  # csv
            fieldnames = [
                "id",
                "title",
                "severity",
                "cvss_score",
                "asset_host",
                "cves",
                "first_seen_at",
                "last_seen_at",
                "status",
            ]
            output = StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            yield output.getvalue()
            output.truncate(0)
            output.seek(0)

            for f in findings:
                row = _export_row(f)
                writer.writerow(row)
                yield output.getvalue()
                output.truncate(0)
                output.seek(0)

    media_type = "application/x-ndjson" if format == "jsonl" else "text/csv"
    filename = f"findings.{format}"
    return StreamingResponse(
        generate(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    result = (
        db.table("findings")
        .select("*, assets(name, host)")
        .eq("id", finding_id)
        .eq("org_id", user["org_id"])
        .single()
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail="Finding not found")

    # How many incidents this finding belongs to — drives the "not linked to an
    # incident" nudge in the UI for high-priority (SSVC "act") findings.
    finding = result.data
    links = (
        db.table("incident_findings")
        .select("incident_id")
        .eq("finding_id", finding_id)
        .execute()
        .data
        or []
    )
    finding["incident_count"] = len(links)
    return finding


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    body: FindingStatusUpdate,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    _assert_owned(db, finding_id, user["org_id"])
    result = db.table("findings").update({"status": body.status}).eq("id", finding_id).execute()
    if not result.data:
        # Update affected no rows (race with a delete, or RLS) — 404 instead of IndexError 500.
        raise HTTPException(status_code=404, detail="Finding not found")
    row = result.data[0]

    # Reflection loop: a human judgement on this finding becomes a prior for future scans
    # (false positive → auto-suppress lookalikes; resolved/accepted → trust them). Best-effort.
    verdict = verdict_memory.STATUS_TO_VERDICT.get(body.status)
    if verdict:
        verdict_memory.record_human_verdict(
            user["org_id"], row, verdict, source="status", user_id=user["id"], db=db
        )
    return row


@router.get("/{finding_id}/suggestions")
async def list_suggestions(
    finding_id: str,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    _assert_owned(db, finding_id, user["org_id"])
    result = (
        db.table("agent_suggestions")
        .select("*")
        .eq("finding_id", finding_id)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


class BulkAction(BaseModel):
    ids: List[str]
    action: str  # "mark_false_positive" | "accept_risk" | "mark_open" | "mark_resolved"


@router.post("/bulk")
async def bulk_update_findings(
    body: BulkAction,
    user=Depends(get_current_user),
    db: Client = Depends(get_db),
):
    ACTION_TO_STATUS = {
        "mark_false_positive": "false_positive",
        "accept_risk": "accepted_risk",
        "mark_open": "open",
        "mark_resolved": "resolved",
    }
    if body.action not in ACTION_TO_STATUS:
        raise HTTPException(400, f"unknown action: {body.action}")
    if not body.ids:
        raise HTTPException(400, "ids must not be empty")

    new_status = ACTION_TO_STATUS[body.action]
    db.table("findings").update({"status": new_status}).in_("id", body.ids).eq("org_id", user["org_id"]).execute()
    return {"updated": len(body.ids)}


@router.post("/import")
async def import_findings(
    file: UploadFile = File(...),
    source: str = Form(...),
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Import findings from Nuclei JSONL or generic JSON array."""
    if source not in ("nuclei", "generic"):
        raise HTTPException(status_code=400, detail="source must be 'nuclei' or 'generic'")

    try:
        content = await file.read()
        text = content.decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    if source == "nuclei":
        rows = _parse_nuclei_jsonl(text)
    else:
        rows = _parse_generic_json(text)

    imported = 0
    skipped = 0
    now = datetime.now(timezone.utc).isoformat()

    # Pre-fetch assets in this org
    assets_result = db.table("assets").select("id, host").eq("org_id", user["org_id"]).execute()
    assets_by_host = {a["host"]: a["id"] for a in (assets_result.data or [])}

    for row in rows:
        host = row.get("host")
        asset_id = assets_by_host.get(host) if host else None

        title = row.get("title", "")
        severity = row.get("severity", "info").lower()
        is_noise = is_absence_finding(title, severity)

        # Skip if it's noise (optional: could include it with is_noise=true)
        if is_noise:
            skipped += 1
            continue

        raw_data = {
            "import_source": source,
            "cvss_v3_score": row.get("cvss_score"),
        }

        # Generate fingerprint: hash of title + host + source for deduplication
        import hashlib
        fingerprint_str = f"{title}|{row.get('host', '')}|{source}"
        fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:32]

        try:
            # Upsert on (org_id, fingerprint) so re-importing the same file refreshes
            # last_seen_at instead of duplicating or failing the unique constraint.
            # created_at is omitted on purpose: the column default sets it on insert and
            # upsert leaves it untouched on conflict, preserving the original timestamp.
            db.table("findings").upsert(
                {
                    "org_id": user["org_id"],
                    "asset_id": asset_id,
                    "title": title,
                    "description": row.get("description", ""),
                    "severity": severity,
                    "cve_ids": row.get("cve_ids", []),
                    "status": "open",
                    "is_noise": is_noise,
                    "raw_data": raw_data,
                    "fingerprint": fingerprint,
                    "last_seen_at": now,
                },
                on_conflict="org_id,fingerprint",
            ).execute()
            imported += 1
        except Exception as e:
            logger.warning(f"Failed to insert finding: {e}")
            continue

    return {
        "imported": imported,
        "skipped": skipped,
        "total": len(rows),
    }


def _parse_nuclei_jsonl(text: str) -> List[dict]:
    """Parse Nuclei JSONL output."""
    rows = []
    for line in text.strip().split("\n"):
        if not line:
            continue
        try:
            obj = json.loads(line)
            info = obj.get("info", {})
            cve_ids = info.get("classification", {}).get("cve-id", [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]

            rows.append(
                {
                    "title": info.get("name", ""),
                    "severity": info.get("severity", "info").lower(),
                    "host": obj.get("host", ""),
                    "description": info.get("description", ""),
                    "cve_ids": cve_ids,
                    "cvss_score": None,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to parse Nuclei line: {e}")
            continue
    return rows


def _parse_generic_json(text: str) -> List[dict]:
    """Parse generic JSON array format."""
    try:
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("Expected JSON array")
        rows = []
        for item in data:
            cve = item.get("cve", "")
            cve_ids = [cve] if cve else []
            rows.append(
                {
                    "title": item.get("title", ""),
                    "severity": item.get("severity", "info").lower(),
                    "host": item.get("host", ""),
                    "description": item.get("description", ""),
                    "cve_ids": cve_ids,
                    "cvss_score": item.get("cvss_score"),
                }
            )
        return rows
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")


def _export_row(finding: dict) -> dict:
    """Convert a finding to SIEM export format."""
    asset = finding.get("assets") or {}
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "cvss_score": finding.get("raw_data", {}).get("cvss_v3_score"),
        "asset_host": asset.get("host"),
        "cves": ",".join(finding.get("cve_ids", []) or []),
        "first_seen_at": finding.get("created_at"),
        "last_seen_at": finding.get("last_seen_at"),
        "status": finding.get("status"),
    }


def _assert_owned(db: Client, finding_id: str, org_id: str):
    r = db.table("findings").select("id").eq("id", finding_id).eq("org_id", org_id).execute()
    if not r.data:
        raise HTTPException(status_code=404, detail="Finding not found")
