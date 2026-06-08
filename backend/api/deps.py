from fastapi import Depends, HTTPException, status
from backend.api.auth import get_current_user

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
