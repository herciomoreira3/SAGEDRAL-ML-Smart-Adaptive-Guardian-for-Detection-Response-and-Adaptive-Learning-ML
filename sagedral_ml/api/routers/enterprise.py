"""Enterprise administration, audit, user, drift, and system event APIs."""

from typing import List, Literal, Optional

import time

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.api.auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    get_current_user,
    require_roles,
)
from sagedral_ml.auth.security import hash_password
from sagedral_ml.core.container import global_container
from sagedral_ml.database import crud
from sagedral_ml.database.connection import get_db
from sagedral_ml.database.models import AlertFeedbackModel, SystemEventModel
from sagedral_ml.database.models import UserModel
from sagedral_ml.ha import ha_sync_manager
from sagedral_ml.ips.response import validate_ip_or_network

router = APIRouter(prefix="/api/v1", tags=["Enterprise"])


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=12, max_length=128)
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    full_name: Optional[str] = Field(None, max_length=150)
    email: Optional[str] = Field(None, max_length=255)


class UserUpdateRequest(BaseModel):
    role: Optional[Literal["admin", "analyst", "viewer"]] = None
    full_name: Optional[str] = Field(None, max_length=150)
    email: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=12, max_length=128)


class HABlockedIPItem(BaseModel):
    ip: str
    reason: Optional[str] = None
    auto_unblock_at: Optional[float] = None
    blocked_at: Optional[float] = None


class HABlocklistRequest(BaseModel):
    source_node: str = Field(..., max_length=100)
    blocked_ips: List[HABlockedIPItem]


@router.get(
    "/audit-logs",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    username: Optional[str] = None,
    action_type: Optional[str] = None,
    target_entity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN)),
):
    rows, total = await crud.get_audit_logs(
        db,
        page=page,
        limit=limit,
        username=username,
        action_type=action_type,
        target_entity=target_entity,
    )
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "data": [row.to_dict() for row in rows],
    }


@router.get("/users", dependencies=[Depends(require_roles(ROLE_ADMIN))])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN)),
):
    return {"data": [user.to_dict() for user in await crud.get_users(db)]}


@router.post(
    "/users",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def add_user(
    payload: UserCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles(ROLE_ADMIN)),
):
    username = payload.username.strip()
    if not username.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(
            status_code=422,
            detail="Username hanya boleh berisi huruf, angka, '-' dan '_'.",
        )
    if await crud.get_user_by_username(db, username):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = await crud.create_user(
        db,
        {
            "username": username,
            "password_hash": hash_password(payload.password),
            "role": payload.role,
            "full_name": payload.full_name,
            "email": payload.email,
        },
    )
    await crud.create_audit_log(
        db,
        "CREATE_USER",
        user=current_user,
        target_entity="user",
        target_id=str(user.id),
        ip_address=request.client.host if request.client else None,
        detail={"username": user.username, "role": user.role},
    )
    return user.to_dict()


@router.put(
    "/users/{user_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def edit_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles(ROLE_ADMIN)),
):
    if user_id == getattr(current_user, "id", None) and payload.is_active is False:
        raise HTTPException(status_code=409, detail="Admin cannot disable own account")
    values = {}
    for field in ("role", "full_name", "email", "is_active"):
        value = getattr(payload, field)
        if value is not None:
            values[field] = int(value) if field == "is_active" else value
    if payload.password:
        values["password_hash"] = hash_password(payload.password)
    updated = await crud.update_user(db, user_id, values)
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found")
    await crud.create_audit_log(
        db,
        "UPDATE_USER",
        user=current_user,
        target_entity="user",
        target_id=str(user_id),
        ip_address=request.client.host if request.client else None,
        detail={"fields": sorted(values.keys())},
    )
    return updated.to_dict()


@router.delete(
    "/users/{user_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def remove_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_roles(ROLE_ADMIN)),
):
    if user_id == getattr(current_user, "id", None):
        raise HTTPException(status_code=409, detail="Admin cannot delete own account")
    target_result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    target = target_result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.role == ROLE_ADMIN and bool(target.is_active):
        count_result = await db.execute(
            select(func.count(UserModel.id)).where(
                UserModel.role == ROLE_ADMIN,
                UserModel.is_active == 1,
            )
        )
        if int(count_result.scalar() or 0) <= 1:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete the last active administrator",
            )
    deleted = await crud.delete_user(db, user_id)
    await crud.create_audit_log(
        db,
        "DELETE_USER",
        user=current_user,
        target_entity="user",
        target_id=str(user_id),
        ip_address=request.client.host if request.client else None,
        detail={"username": deleted.username if deleted else None},
    )
    return {"success": True, "user_id": user_id}


@router.get(
    "/system/events",
    dependencies=[Depends(get_current_user)],
)
async def list_system_events(
    limit: int = Query(100, ge=1, le=500),
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    statement = select(SystemEventModel)
    if event_type:
        statement = statement.where(SystemEventModel.event_type == event_type)
    statement = statement.order_by(SystemEventModel.timestamp.desc()).limit(limit)
    result = await db.execute(statement)
    return {"data": [row.to_dict() for row in result.scalars().all()]}


@router.get("/model/drift", dependencies=[Depends(get_current_user)])
async def model_drift(_user=Depends(get_current_user)):
    engine = global_container.ml_engine
    if engine is None:
        return {
            "detected": False,
            "available": False,
            "message": "ML engine is not attached in API-only mode.",
        }
    return dict(engine.get_drift_status(), available=True)


@router.post(
    "/model/reload",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def reload_model(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    engine = global_container.ml_engine
    if engine is None:
        raise HTTPException(status_code=503, detail="ML engine unavailable")
    loaded = bool(engine.load_models())
    await crud.create_audit_log(
        db,
        "RELOAD_MODEL",
        user=user,
        target_entity="model",
        target_id=engine.version,
        ip_address=request.client.host if request.client else None,
        detail={"loaded": loaded},
    )
    return {"success": loaded, "version": engine.version}


@router.get(
    "/feedback/status",
    dependencies=[Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN))],
)
async def feedback_status(
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ANALYST, ROLE_ADMIN)),
):
    pending = await db.execute(
        select(func.count(AlertFeedbackModel.id)).where(
            AlertFeedbackModel.processed_at.is_(None)
        )
    )
    eligible = await db.execute(
        select(func.count(AlertFeedbackModel.id)).where(
            AlertFeedbackModel.processed_at.is_(None),
            AlertFeedbackModel.label != "UNCERTAIN",
        )
    )
    total = await db.execute(select(func.count(AlertFeedbackModel.id)))
    return {
        "pending": int(pending.scalar() or 0),
        "eligible_for_training": int(eligible.scalar() or 0),
        "total": int(total.scalar() or 0),
    }


@router.post(
    "/feedback/retrain",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def retrain_from_feedback(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    from sagedral_ml.adaptive import adaptive_learning_manager

    result = await adaptive_learning_manager.run_once()
    await crud.create_audit_log(
        db,
        "RETRAIN_FROM_FEEDBACK",
        user=user,
        target_entity="model",
        target_id=str(result.get("version", "none")),
        ip_address=request.client.host if request.client else None,
        detail=result,
    )
    return result


@router.post("/ha/blocklist", include_in_schema=False)
async def receive_ha_blocklist(
    payload: HABlocklistRequest,
    x_sagedral_ha_key: str = Header("", alias="X-Sagedral-HA-Key"),
    db: AsyncSession = Depends(get_db),
):
    if not ha_sync_manager.enabled() or not ha_sync_manager.valid_secret(
        x_sagedral_ha_key
    ):
        raise HTTPException(status_code=403, detail="Invalid HA peer credentials")
    if len(payload.blocked_ips) > 10000:
        raise HTTPException(status_code=422, detail="HA blocklist exceeds 10000 entries")
    ips_module = global_container.ips_module
    applied = 0
    for item in payload.blocked_ips:
        try:
            clean_ip = validate_ip_or_network(item.ip)
        except ValueError:
            continue
        if ips_module is not None:
            if "/" in clean_ip:
                if ips_module.is_entry_whitelisted(clean_ip):
                    continue
                if not ips_module.block_network(clean_ip):
                    continue
            else:
                if ips_module.is_whitelisted(clean_ip):
                    continue
                if not ips_module.block_ip(clean_ip):
                    continue
        duration = None
        if item.auto_unblock_at:
            duration = max(0, int(item.auto_unblock_at - time.time()))
        await crud.block_ip_db(
            db,
            clean_ip,
            reason=item.reason or "HA peer synchronization",
            duration_seconds=duration,
            blocked_by="ha:%s" % payload.source_node,
        )
        applied += 1
    return {"success": True, "applied": applied}
