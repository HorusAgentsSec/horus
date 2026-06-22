import time
import hashlib
import secrets
from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import Client
from typing import Optional

from backend.core.supabase_client import supabase, get_authed_client

bearer = HTTPBearer(auto_error=False)

# In-memory TTL cache: user_id -> (profile_data, expires_at).
# We cache only the DB profile lookup, NOT the JWT validation: the token is
# revalidated with Supabase on every request (cheap, and the only thing that
# catches a revoked/expired/logged-out token), so a stale token is never accepted.
_CACHE: dict[str, tuple[dict, float]] = {}
_TTL_SECONDS = 30


def evict_user_sessions(user_id: str) -> None:
    """Drop the cached profile for a user (call after password change)."""
    _CACHE.pop(user_id, None)


# Short-lived single-use tickets for SSE/EventSource, which cannot send an
# Authorization header. The ticket travels in the query string instead of the JWT,
# so a leak in proxy/access logs is worthless: it is consumed on first use and
# expires in seconds. In-memory is fine for the single-process deployment (same as
# _CACHE / cancel.py); move to Redis if you ever run multiple workers.
_STREAM_TICKETS: dict[str, tuple[dict, float]] = {}
_STREAM_TICKET_TTL = 30


def mint_stream_ticket(user: dict) -> str:
    now = time.time()
    # opportunistic prune of expired tickets so the dict cannot grow unbounded
    for k in [k for k, v in _STREAM_TICKETS.items() if v[1] < now]:
        _STREAM_TICKETS.pop(k, None)
    ticket = secrets.token_urlsafe(32)
    _STREAM_TICKETS[ticket] = (user, now + _STREAM_TICKET_TTL)
    return ticket


def consume_stream_ticket(ticket: str) -> dict:
    """Validate and burn a stream ticket. Raises 401 if missing/expired/already used."""
    entry = _STREAM_TICKETS.pop(ticket, None)  # pop = single use
    if not entry or entry[1] < time.time():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired stream ticket")
    return entry[0]


def _resolve_api_key(key: str) -> dict:
    """Resolve an API key (hrs_...) to a user dict scoped to its org and role."""
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    try:
        result = (
            supabase.table("api_keys")
            .select("id, org_id, role")
            .eq("key_hash", key_hash)
            .is_("revoked_at", "null")
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

        row = result.data
        # Update last_used_at asynchronously (best-effort, don't block the request)
        try:
            from datetime import datetime, timezone
            supabase.table("api_keys").update(
                {"last_used_at": datetime.now(timezone.utc).isoformat()}
            ).eq("id", row["id"]).execute()
        except Exception:
            pass  # Best-effort; don't fail the request if audit fails

        return {
            "id": f"apikey:{row['id']}",
            "org_id": row["org_id"],
            "role": row["role"],
            "token": key,
            "is_api_key": True,
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def _resolve_user(token: str) -> dict:
    # Always validate the JWT against Supabase: this is what catches an expired,
    # revoked, or signed-out token. Only the profile lookup below is cached.
    try:
        result = supabase.auth.get_user(token)
        user = result.user
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    cached = _CACHE.get(user.id)
    if cached and cached[1] > time.time():
        profile_data = cached[0]
    else:
        profile = (
            supabase.table("profiles")
            .select("org_id, role, must_change_password")
            .eq("id", user.id)
            .single()
            .execute()
        )
        if not profile.data:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No profile found")
        profile_data = profile.data
        _CACHE[user.id] = (profile_data, time.time() + _TTL_SECONDS)

    return {
        "id": user.id,
        "email": user.email,
        "org_id": profile_data["org_id"],
        "role": profile_data["role"],
        "must_change_password": bool(profile_data.get("must_change_password")),
        "token": token,
    }


# Endpoints reachable while must_change_password is still set (matched by path suffix).
# The forced-password-change flow needs the user to be able to set a new password;
# everything else is blocked server-side until they do.
_PASSWORD_CHANGE_EXEMPT = ("/account/change-password",)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    x_api_key: Optional[str] = Header(None),
) -> dict:
    # API key takes precedence if provided. API keys are machine credentials and never
    # carry the must_change_password flag, so they skip that gate entirely.
    if x_api_key:
        return _resolve_api_key(x_api_key)
    # Fall back to Bearer token
    if credentials:
        user = _resolve_user(credentials.credentials)
        # Enforce the forced-password-change gate on the SERVER, not just in React:
        # an invited user with the temp password has a valid JWT and could otherwise
        # call any endpoint directly (curl/Postman) until they change it.
        if user.get("must_change_password") and not request.url.path.endswith(_PASSWORD_CHANGE_EXEMPT):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password change required",
            )
        return user
    # Neither API key nor Bearer token provided
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")


async def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    """
    Validates the JWT but does NOT require an existing profile.

    Used by onboarding, where a freshly signed-up user has a valid session but no
    profile/org yet. Returns {id, email, token} only.
    """
    token = credentials.credentials
    try:
        result = supabase.auth.get_user(token)
        user = result.user
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return {"id": user.id, "email": user.email, "token": token}


async def get_db(user: dict = Depends(get_current_user)) -> Client:
    """
    Returns a Supabase client scoped to the requesting user's JWT, so RLS
    policies enforce org isolation. For API keys, we use the admin client
    and rely on Postgres RLS to filter by org_id in the user dict.
    """
    # API keys don't have a valid JWT, so use the admin client
    if user.get("is_api_key"):
        return supabase
    # Regular Bearer token users get an authed client
    return get_authed_client(user["token"])
