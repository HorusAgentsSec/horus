from fastapi import Depends, HTTPException, status
from backend.api.auth import get_authenticated_user, get_current_user
from backend.core.config import settings

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}


def require_role(minimum_role: str):
    """
    Dependency factory — rejects requests from users below the minimum role.
    Usage: Depends(require_role("admin"))
    """
    async def check(user: dict = Depends(get_current_user)) -> dict:
        user_level = ROLE_HIERARCHY.get(user.get("role", "viewer"), 0)
        required_level = ROLE_HIERARCHY.get(minimum_role, 99)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum_role} role or higher",
            )
        return user
    return check


async def require_superadmin(auth: dict = Depends(get_authenticated_user)) -> dict:
    """Gate for the cross-org Horus super-admin panel (SUPERADMIN_EMAILS allowlist).

    Uses get_authenticated_user (has email, no profile required) so a super-admin need
    not belong to any tenant org. Empty allowlist = nobody is a super-admin.
    """
    allow = {e.strip().lower() for e in settings.superadmin_emails.split(",") if e.strip()}
    if not allow or (auth.get("email") or "").lower() not in allow:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return auth
