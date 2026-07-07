"""
Audit logging — append-only trail of security-relevant actions.

For a blue-team tool this is foundational: forensics + compliance require knowing
who approved which AI suggestion, who changed a role, who deleted an asset.

Writes use the service-role client because audit entries are system-generated and
must never be blocked by RLS or be tamperable by the acting user. Failures here
must NEVER break the underlying operation — logging is best-effort.
"""

import logging

from backend.core.supabase_client import supabase

logger = logging.getLogger(__name__)


def log_action(
    org_id: str,
    actor_id: str,
    action: str,
    *,
    actor_type: str = "user",
    entity_type: str | None = None,
    entity_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Records one audit entry. Best-effort: swallows its own errors."""
    try:
        supabase.table("audit_log").insert({
            "org_id": org_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "metadata": metadata or {},
        }).execute()
    except Exception as e:
        logger.error(f"Audit log write failed for action '{action}': {e}")
