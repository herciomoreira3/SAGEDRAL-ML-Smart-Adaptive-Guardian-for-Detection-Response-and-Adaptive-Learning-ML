"""
API Router for Traffic statistics endpoints.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud

from sagedral_ml.api.auth import get_current_user


router = APIRouter(prefix="/api/v1/traffic", tags=["Traffic"])


@router.get("/stats", dependencies=[Depends(get_current_user)])
async def get_traffic_stats(
    interval: str = Query("1m", pattern="^(1m|5m|1h|24h)$"),
    limit: int = Query(60, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    stats = await crud.get_traffic_stats(db, limit=limit)
    data = [s.to_dict() for s in stats]
    return {"interval": interval, "data": data}
