"""
API Router for Authentication endpoints.
Handles user login (OAuth2 password flow) and current user profile retrieval.
"""

import json
import time
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database.models import UserModel, AuditLogModel
from sagedral_ml.auth.security import (
    verify_password,
    create_access_token,
    get_current_user,
    UserProfile as _SecurityUserProfile,
)
from sagedral_ml.api.schemas.auth import LoginResponse, UserProfile

logger = logging.getLogger("sagedral_ml.api.routers.auth")

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _user_to_profile(user: UserModel) -> UserProfile:
    return UserProfile(
        id=user.id,
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        email=user.email,
        is_active=bool(user.is_active),
        created_at=user.created_at,
        last_login=user.last_login,
    )


def _get_client_ip(request: Request) -> str:
    try:
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"


def _get_user_agent(request: Request) -> str:
    ua = request.headers.get("user-agent", "")
    return ua[:500] if ua else ""


async def _write_audit_log(
    db: AsyncSession,
    user: Optional[UserModel],
    action_type: str,
    request: Request,
    target_entity: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    try:
        detail_json = json.dumps(detail) if detail is not None else None
        log = AuditLogModel(
            timestamp=time.time(),
            user_id=user.id if user else None,
            username=user.username if user else None,
            action_type=action_type,
            target_entity=target_entity,
            target_id=target_id,
            ip_address=_get_client_ip(request),
            user_agent=_get_user_agent(request),
            detail_json=detail_json,
        )
        db.add(log)
        await db.commit()
    except Exception as e:
        logger.warning(f"Gagal menulis audit log action={action_type}: {e}")


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    username = form_data.username.strip() if form_data.username else ""

    if not username or not form_data.password:
        await _write_audit_log(
            db, None, "login_failed", request,
            target_entity="user", target_id=username or "<empty>",
            detail={"reason": "empty_credentials", "ip": ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username dan password wajib diisi.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = select(UserModel).where(UserModel.username == username)
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if user is None:
        await _write_audit_log(
            db, None, "login_failed", request,
            target_entity="user", target_id=username,
            detail={"reason": "user_not_found", "ip": ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username atau password salah.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not bool(user.is_active):
        await _write_audit_log(
            db, user, "login_failed", request,
            target_entity="user", target_id=username,
            detail={"reason": "user_disabled", "ip": ip},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akun ini sudah dinonaktifkan. Hubungi administrator.",
        )

    if not verify_password(form_data.password, user.password_hash):
        await _write_audit_log(
            db, user, "login_failed", request,
            target_entity="user", target_id=username,
            detail={"reason": "wrong_password", "ip": ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username atau password salah.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = time.time()
    stmt_update = (
        update(UserModel)
        .where(UserModel.id == user.id)
        .values(last_login=now)
    )
    try:
        await db.execute(stmt_update)
        await db.commit()
        user.last_login = now
    except Exception as e:
        logger.warning(f"Gagal update last_login user {username}: {e}")

    access_token = create_access_token(
        subject=user.id,
        username=user.username,
        role=user.role,
    )

    await _write_audit_log(
        db, user, "login_success", request,
        target_entity="user", target_id=username,
        detail={"ip": ip, "role": user.role},
    )

    logger.info(f"User '{username}' (role={user.role}) login berhasil dari IP {ip}")

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=_user_to_profile(user),
    )


@router.get("/me", response_model=UserProfile)
async def get_me(
    request: Request,
    current_user: UserModel = Depends(get_current_user),
):
    return _user_to_profile(current_user)
