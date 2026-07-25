"""
API Router for Blocked IP management endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.blocked_ip import (
    BlockedIPListResponse,
    BlockedIPItem,
    BlockIPRequest,
    ActionResponse,
)
from sagedral_ml.ips.response import validate_ip, validate_ip_or_network, HARDCODED_WHITELIST
from sagedral_ml.config import get_config
from sagedral_ml.core.container import global_container
from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ADMIN, ROLE_ANALYST


class WhitelistItem(BaseModel):
    ip: str
    note: Optional[str] = ""


class WhitelistListResponse(BaseModel):
    total: int
    data: List[WhitelistItem]


router = APIRouter(prefix="/api/v1/blocked-ips", tags=["Blocked IPs"])


def _get_ips_module():
    if global_container is not None:
        return getattr(global_container, "ips_module", None) or getattr(router, "ips_module", None)
    return getattr(router, "ips_module", None)


@router.get("", response_model=BlockedIPListResponse, dependencies=[Depends(get_current_user)])
async def get_blocked_ips(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    blocked_ips = await crud.get_active_blocked_ips(db)
    items = [BlockedIPItem(**b.to_dict()) for b in blocked_ips]
    return BlockedIPListResponse(total=len(items), data=items)


def _persist_whitelist_config(config) -> None:
    if not config.save():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist whitelist changes to config TOML file.",
        )


@router.post("", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST))])
async def manual_block_ip(
    req: BlockIPRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST)),
):
    try:
        clean_ip = validate_ip(req.ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    global_ips_module = _get_ips_module()
    if global_ips_module and global_ips_module.is_whitelisted(clean_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"IP address '{clean_ip}' is whitelisted and cannot be blocked.",
        )
    if clean_ip in HARDCODED_WHITELIST:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"IP address '{clean_ip}' is whitelisted and cannot be blocked.",
        )

    if global_ips_module:
        success = global_ips_module.block_ip(clean_ip)
        if not success and global_ips_module.is_whitelisted(clean_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"IP address '{clean_ip}' is whitelisted.",
            )

    await crud.block_ip_db(
        db,
        ip=clean_ip,
        reason=req.reason or "Manual block",
        duration_seconds=req.duration_seconds,
        blocked_by="manual",
    )

    return ActionResponse(success=True, message=f"IP address {clean_ip} successfully blocked.")


@router.delete("/{ip}", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST))])
async def manual_unblock_ip(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST)),
):
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    global_ips_module = _get_ips_module()
    if global_ips_module:
        global_ips_module.unblock_ip(clean_ip)

    unblocked = await crud.unblock_ip_db(db, clean_ip)
    if not unblocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address {clean_ip} was not found in active block list.",
        )

    return ActionResponse(success=True, message=f"IP address {clean_ip} successfully unblocked.")


@router.get("/whitelist", response_model=WhitelistListResponse, dependencies=[Depends(get_current_user)])
async def get_whitelist(_user=Depends(get_current_user)):
    config = get_config()
    whitelist_data = config.get("ips", "whitelist", [])
    items: List[WhitelistItem] = []
    if isinstance(whitelist_data, list):
        if whitelist_data and isinstance(whitelist_data[0], dict):
            items = [WhitelistItem(**{k: v for k, v in w.items() if k in ("ip", "note")}) for w in whitelist_data]
        else:
            items = [WhitelistItem(ip=str(w), note="") for w in whitelist_data]
    return WhitelistListResponse(total=len(items), data=items)


@router.post("/whitelist", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN))])
async def add_whitelist(item: WhitelistItem, _user=Depends(require_roles(ROLE_ADMIN))):
    try:
        clean_entry = validate_ip_or_network(item.ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    config = get_config()
    ips_section = config._data.setdefault("ips", {})
    whitelist = ips_section.setdefault("whitelist", [])

    if isinstance(whitelist, list):
        existing_entries = set()
        for w in whitelist:
            if isinstance(w, dict):
                existing_entries.add(str(w.get("ip", "")))
            else:
                existing_entries.add(str(w))
        if clean_entry in existing_entries:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Entry '{clean_entry}' is already in whitelist.",
            )
        whitelist.append({"ip": clean_entry, "note": item.note or ""})
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Whitelist configuration is not in expected format.",
        )

    ips_module = _get_ips_module()
    if ips_module:
        ips_module.add_to_whitelist(clean_entry)

    _persist_whitelist_config(config)
    return ActionResponse(success=True, message=f"Entry {clean_entry} added to whitelist.")


@router.delete("/whitelist/{ip:path}", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN))])
async def remove_whitelist(ip: str, _user=Depends(require_roles(ROLE_ADMIN))):
    try:
        clean_ip = validate_ip_or_network(ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    config = get_config()
    ips_section = config._data.setdefault("ips", {})
    whitelist = ips_section.setdefault("whitelist", [])

    if not isinstance(whitelist, list):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Whitelist configuration is not in expected format.",
        )

    found_idx = -1
    for i, w in enumerate(whitelist):
        if isinstance(w, dict):
            if w.get("ip") == clean_ip:
                found_idx = i
                break
        elif str(w) == clean_ip:
            found_idx = i
            break

    if found_idx == -1:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{clean_ip}' was not found in whitelist.",
        )

    whitelist.pop(found_idx)

    ips_module = _get_ips_module()
    if ips_module:
        ips_module.remove_from_whitelist(clean_ip)

    _persist_whitelist_config(config)
    return ActionResponse(success=True, message=f"Entry {clean_ip} removed from whitelist.")
