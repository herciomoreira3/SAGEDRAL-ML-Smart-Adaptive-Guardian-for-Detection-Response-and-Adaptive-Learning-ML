"""
API Router for Security Alerts endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.alert import AlertListResponse, AlertItem

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
):
    alerts, total = await crud.get_alerts(
        db,
        page=page,
        limit=limit,
        severity=severity,
        attack_type=attack_type,
        src_ip=src_ip,
        start_time=start_time,
        end_time=end_time,
    )
    items = [AlertItem(**a.to_dict()) for a in alerts]
    return AlertListResponse(total=total, page=page, limit=limit, data=items)
