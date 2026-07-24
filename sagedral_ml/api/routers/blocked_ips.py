"""
API Router for Blocked IP management endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.blocked_ip import (
    BlockedIPListResponse,
    BlockedIPItem,
    BlockIPRequest,
    ActionResponse,
)
from sagedral_ml.ips.response import validate_ip, HARDCODED_WHITELIST
from sagedral_ml.config import get_config

router = APIRouter(prefix="/api/v1/blocked-ips", tags=["Blocked IPs"])


@router.get("", response_model=BlockedIPListResponse)
async def get_blocked_ips(db: AsyncSession = Depends(get_db)):
    blocked_ips = await crud.get_active_blocked_ips(db)
    items = [BlockedIPItem(**b.to_dict()) for b in blocked_ips]
    return BlockedIPListResponse(total=len(items), data=items)


@router.post("", response_model=ActionResponse)
async def manual_block_ip(req: BlockIPRequest, db: AsyncSession = Depends(get_db)):
    try:
        clean_ip = validate_ip(req.ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    config = get_config()
    whitelist = set(config.get("ips", "whitelist", []))
    if clean_ip in HARDCODED_WHITELIST or clean_ip in whitelist:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"IP address '{clean_ip}' is whitelisted and cannot be blocked.",
        )

    # Execute IPS block command
    global_ips_module = getattr(router, "ips_module", None)
    if global_ips_module:
        success = global_ips_module.block_ip(clean_ip)
        if not success and global_ips_module.is_whitelisted(clean_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"IP address '{clean_ip}' is whitelisted.",
            )

    # Persist in DB
    await crud.block_ip_db(
        db,
        ip=clean_ip,
        reason=req.reason or "Manual block",
        duration_seconds=req.duration_seconds,
        blocked_by="manual",
    )

    return ActionResponse(success=True, message=f"IP address {clean_ip} successfully blocked.")


@router.delete("/{ip}", response_model=ActionResponse)
async def manual_unblock_ip(ip: str, db: AsyncSession = Depends(get_db)):
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    global_ips_module = getattr(router, "ips_module", None)
    if global_ips_module:
        global_ips_module.unblock_ip(clean_ip)

    unblocked = await crud.unblock_ip_db(db, clean_ip)
    if not unblocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address {clean_ip} was not found in active block list.",
        )

    return ActionResponse(success=True, message=f"IP address {clean_ip} successfully unblocked.")
