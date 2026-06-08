"""
Privacy API — surfaces the deployment's data-privacy posture (read-only).

Lets the UI show "where does your data go" as a trust signal. Deployment-level (env-configured),
so it's the same for everyone in the instance; auth is required but no org scoping is needed.
"""

from fastapi import APIRouter, Depends

from backend.api.auth import get_current_user
from backend.core.privacy import privacy_status

router = APIRouter(prefix="/privacy", tags=["privacy"])


@router.get("")
async def get_privacy(user=Depends(get_current_user)):
    return privacy_status()
