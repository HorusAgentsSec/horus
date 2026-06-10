import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from supabase import Client

from backend.api.auth import get_current_user, get_db

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class ApiKeyCreate(BaseModel):
    name: str
    role: str = "analyst"  # analyst | admin


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    role: str
    created_at: str
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


class ApiKeySecret(BaseModel):
    """Response when creating an API key; includes the secret ONE time."""

    id: str
    name: str
    key_prefix: str
    secret: str  # hrs_<32 random chars>
    role: str
    created_at: str


def _assert_admin(user: dict):
    """Only admins can manage API keys."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")


@router.get("", response_model=list[ApiKeyResponse])
async def list_api_keys(
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """List all API keys for the organization (admin only)."""
    _assert_admin(user)

    result = (
        db.table("api_keys")
        .select("id, name, key_prefix, role, created_at, last_used_at, revoked_at")
        .eq("org_id", user["org_id"])
        .is_("revoked_at", "null")
        .order("created_at", desc=True)
        .execute()
    )
    return result.data or []


@router.post("", response_model=ApiKeySecret, status_code=201)
async def create_api_key(
    body: ApiKeyCreate,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Create a new API key (admin only). The secret is returned ONLY here."""
    _assert_admin(user)

    if body.role not in ("analyst", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")

    # Generate: hrs_<32 random alphanumeric>
    secret = "hrs_" + secrets.token_urlsafe(24)[:32]
    key_hash = hashlib.sha256(secret.encode()).hexdigest()
    key_prefix = secret[:12]  # hrs_<8 chars>

    now = datetime.now(timezone.utc).isoformat()
    try:
        result = db.table("api_keys").insert(
            {
                "org_id": user["org_id"],
                "name": body.name,
                "key_hash": key_hash,
                "key_prefix": key_prefix,
                "role": body.role,
                "created_by": user["id"],
                "created_at": now,
            }
        ).execute()

        row = result.data[0]
        return ApiKeySecret(
            id=row["id"],
            name=row["name"],
            key_prefix=row["key_prefix"],
            secret=secret,
            role=row["role"],
            created_at=row["created_at"],
        )
    except Exception as e:
        if "duplicate key" in str(e).lower():
            raise HTTPException(status_code=400, detail="Key name already exists")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    user: dict = Depends(get_current_user),
    db: Client = Depends(get_db),
):
    """Revoke an API key (admin only)."""
    _assert_admin(user)

    rows = (
        db.table("api_keys")
        .update({"revoked_at": datetime.now(timezone.utc).isoformat()})
        .eq("id", key_id)
        .eq("org_id", user["org_id"])
        .execute()
        .data
    )

    if not rows:
        raise HTTPException(status_code=404, detail="API key not found")
