"""
Asset software inventory — the durable record of what software runs where.

The scan pipeline detects services (product/version/port) but that data is otherwise
ephemeral to a single scan. Watchtower needs it to persist so it can re-correlate the
inventory against newly known-exploited CVEs every day WITHOUT re-scanning. This module
upserts detected services into asset_inventory at scan time.

Best-effort by design: inventory tracking must never break a scan.
"""

import logging
from datetime import datetime, timezone

from backend.core.supabase_client import supabase  # service-role: bypasses RLS

logger = logging.getLogger(__name__)


def record_inventory(org_id: str, asset_id: str, services: list[dict]) -> int:
    """
    Upsert detected services (product/version/port) into the persistent inventory.
    Returns the number of rows written. `last_seen_at` is refreshed on every observation;
    `first_seen_at` is preserved (it is not in the upsert payload, so ON CONFLICT leaves it).
    """
    now = datetime.now(timezone.utc).isoformat()
    rows: list[dict] = []
    seen: set[tuple] = set()
    for svc in services:
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip()
        if not product or not version:
            continue
        try:
            port = int(svc.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        key = (product, version, port)
        if key in seen:  # the same service can appear on several scan lines
            continue
        seen.add(key)
        rows.append(
            {
                "org_id": org_id,
                "asset_id": asset_id,
                "product": product,
                "version": version,
                "port": port,
                "service_name": (svc.get("service") or "").strip() or None,
                "last_seen_at": now,
            }
        )
    if not rows:
        return 0
    supabase.table("asset_inventory").upsert(
        rows, on_conflict="asset_id,product,version,port"
    ).execute()
    logger.info("inventory: recorded %d services for asset %s", len(rows), asset_id)
    return len(rows)
