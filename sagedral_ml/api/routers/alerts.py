"""
API Router for Security Alerts endpoints.
"""

from typing import Optional, Literal
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.alert import AlertListResponse, AlertItem

from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ANALYST, ROLE_ADMIN


class AlertFeedbackRequest(BaseModel):
    label: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"]
    notes: Optional[str] = ""


router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse, dependencies=[Depends(get_current_user)])
async def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
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


@router.post("/{alert_id}/feedback", dependencies=[Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN))])
async def submit_alert_feedback(
    alert_id: str,
    feedback: AlertFeedbackRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN)),
):
    alert_row = await crud.get_alert_by_alert_id(db, alert_id)
    if alert_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id '{alert_id}' not found.",
        )

    username = getattr(user, "username", "analyst") if user else "analyst"
    await crud.create_alert_feedback(db, {
        "alert_id": alert_id,
        "label": feedback.label,
        "notes": feedback.notes,
        "created_by": username,
    })

    return {
        "success": True,
        "message": "Feedback submitted successfully.",
        "alert_id": alert_id,
        "label": feedback.label,
        "notes": feedback.notes,
        "persisted": True,
    }
