"""
API Router for Security Alerts endpoints.
"""

import csv
import io
from typing import List, Optional, Literal
from fastapi import APIRouter, Depends, Query, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.alert import AlertListResponse, AlertItem

from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ANALYST, ROLE_ADMIN


class AlertFeedbackRequest(BaseModel):
    label: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"]
    notes: Optional[str] = Field("", max_length=4000)


class BulkDeleteRequest(BaseModel):
    alert_ids: List[str]


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


@router.get("/export.csv", dependencies=[Depends(get_current_user)])
async def export_alerts_csv(
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    rows, _ = await crud.get_alerts(
        db,
        page=1,
        limit=100000,
        severity=severity,
        attack_type=attack_type,
        src_ip=src_ip,
        start_time=start_time,
        end_time=end_time,
    )
    output = io.StringIO()
    fields = [
        "alert_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "attack_type",
        "severity",
        "final_score",
        "action_taken",
        "signature_matched",
        "src_country",
        "status",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        data = row.to_dict()
        data["signature_matched"] = "|".join(data.get("signature_matched") or [])
        writer.writerow(data)
    filename = "sagedral-alerts.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="%s"' % filename},
    )


@router.post("/{alert_id}/feedback", dependencies=[Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN))])
async def submit_alert_feedback(
    alert_id: str,
    request: Request,
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
    await crud.create_audit_log(
        db,
        "LABEL_ALERT",
        user=user,
        target_entity="alert",
        target_id=alert_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        detail={"label": feedback.label},
    )

    return {
        "success": True,
        "message": "Feedback submitted successfully.",
        "alert_id": alert_id,
        "label": feedback.label,
        "notes": feedback.notes,
        "persisted": True,
    }


@router.post(
    "/{alert_id}/close",
    dependencies=[Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN))],
)
async def close_alert(
    alert_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN)),
):
    if not await crud.close_alert(db, alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    await crud.create_audit_log(
        db,
        "CLOSE_ALERT",
        user=user,
        target_entity="alert",
        target_id=alert_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"success": True, "alert_id": alert_id, "status": "closed"}


@router.delete(
    "/{alert_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def remove_alert(
    alert_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    if not await crud.delete_alert(db, alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    await crud.create_audit_log(
        db,
        "DELETE_ALERT",
        user=user,
        target_entity="alert",
        target_id=alert_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"success": True, "alert_id": alert_id}


@router.post(
    "/bulk-delete",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def bulk_remove_alerts(
    payload: BulkDeleteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    if not payload.alert_ids or len(payload.alert_ids) > 1000:
        raise HTTPException(
            status_code=422, detail="Provide 1-1000 alert IDs"
        )
    deleted = await crud.bulk_delete_alerts(db, payload.alert_ids)
    await crud.create_audit_log(
        db,
        "BULK_DELETE_ALERTS",
        user=user,
        target_entity="alert",
        target_id="bulk",
        ip_address=request.client.host if request.client else None,
        detail={"requested": len(payload.alert_ids), "deleted": deleted},
    )
    return {"success": True, "deleted": deleted}
