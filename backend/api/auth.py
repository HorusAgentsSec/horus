import time

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import Client

from backend.core.supabase_client import supabase, get_authed_client

bearer = HTTPBearer()

# In-memory TTL cache: token -> (user_dict, expires_at).
# Avoids a Supabase round-trip (auth.get_user + profile query) on every request.
_CACHE: dict[str, tuple[dict, float]] = {}
_TTL_SECONDS = 30


def _resolve_user(token: str) -> dict:
    cached = _CACHE.get(token)
    if cached and cached[1] > time.time():
        return cached[0]

    try:
        result = supabase.auth.get_user(token)
        user = result.user
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    profile = (
        supabase.table("profiles")
        .select("org_id, role")
        .eq("id", user.id)
        .single()
        .execute()
    )
    if not profile.data:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No profile found")

    user_dict = {
        "id": user.id,
        "email": user.email,
        "org_id": profile.data["org_id"],
        "role": profile.data["role"],
        "token": token,
    }
    _CACHE[token] = (user_dict, time.time() + _TTL_SECONDS)
    return user_dict


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    return _resolve_user(credentials.credentials)


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
    policies enforce org isolation. Use this for all user-facing data queries.
    """
    return get_authed_client(user["token"])
