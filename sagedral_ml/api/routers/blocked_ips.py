"""
API Router for Blocked IP management endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.blocked_ip import (
    BlockedIPListResponse,
    BlockedIPItem,
    BlockIPRequest,
    ActionResponse,
)
from sagedral_ml.ips.response import (
    validate_ip,
    validate_ip_or_network,
    HARDCODED_WHITELIST,
    calculate_escalated_duration,
)
from sagedral_ml.config import get_config
from sagedral_ml.core.container import global_container
from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ADMIN, ROLE_ANALYST
from sagedral_ml.api.rate_limit import limiter


class WhitelistItem(BaseModel):
    ip: str = Field(..., min_length=2, max_length=45)
    note: Optional[str] = Field("", max_length=500)


class WhitelistListResponse(BaseModel):
    total: int
    data: List[WhitelistItem]


class BulkBlockRequest(BaseModel):
    ips: List[str]
    reason: Optional[str] = Field("Bulk manual block", max_length=1000)
    duration_seconds: Optional[int] = Field(3600, ge=0, le=31536000)


class NetworkBlockRequest(BaseModel):
    network: str = Field(..., min_length=3, max_length=45)
    reason: Optional[str] = Field("Manual CIDR block", max_length=1000)
    duration_seconds: Optional[int] = Field(3600, ge=0, le=31536000)


router = APIRouter(prefix="/api/v1/blocked-ips", tags=["Blocked IPs"])
whitelist_router = APIRouter(prefix="/api/v1/whitelist", tags=["Whitelist"])


def _get_ips_module():
    return global_container.ips_module


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
@limiter.limit("10/minute")
async def manual_block_ip(
    request: Request,
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
        if not success and bool(getattr(global_ips_module, "enabled", False)):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Firewall backend failed to apply the IP block.",
            )

    duration = req.duration_seconds
    if get_config().get("ips", "strike_escalation_enabled", True):
        offense = await crud.record_ip_offense(db, clean_ip)
        duration = calculate_escalated_duration(
            req.duration_seconds, offense.strike_count
        )
    username = getattr(_user, "username", "manual")
    await crud.block_ip_db(
        db,
        ip=clean_ip,
        reason=req.reason or "Manual block",
        duration_seconds=duration,
        blocked_by=username,
    )
    await crud.create_audit_log(
        db,
        "BLOCK_IP",
        user=_user,
        target_entity="ip",
        target_id=clean_ip,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        detail={"reason": req.reason, "duration_seconds": duration},
    )

    return ActionResponse(
        success=True,
        message=f"IP address {clean_ip} successfully blocked.",
    )


@router.delete("/{ip}", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST))])
async def manual_unblock_ip(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST)),
):
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    global_ips_module = _get_ips_module()
    if global_ips_module:
        firewall_ok = global_ips_module.unblock_ip(clean_ip)
        if not firewall_ok and bool(getattr(global_ips_module, "enabled", False)):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Firewall backend failed to remove the IP block.",
            )

    unblocked = await crud.unblock_ip_db(db, clean_ip)
    if not unblocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address {clean_ip} was not found in active block list.",
        )
    await crud.create_audit_log(
        db,
        "UNBLOCK_IP",
        user=_user,
        target_entity="ip",
        target_id=clean_ip,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return ActionResponse(success=True, message=f"IP address {clean_ip} successfully unblocked.")


@router.post(
    "/bulk",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST))],
)
@limiter.limit("3/minute")
async def bulk_block_ips(
    request: Request,
    payload: BulkBlockRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST)),
):
    if not payload.ips or len(payload.ips) > 500:
        raise HTTPException(status_code=422, detail="Provide 1-500 IP addresses")
    module = _get_ips_module()
    results = []
    for raw_ip in payload.ips:
        try:
            clean_ip = validate_ip(raw_ip)
            if module is not None and module.is_whitelisted(clean_ip):
                raise ValueError("whitelisted")
            firewall_ok = module is None or module.block_ip(clean_ip)
            if not firewall_ok:
                raise RuntimeError("firewall_failed")
            await crud.block_ip_db(
                db,
                clean_ip,
                reason=payload.reason or "Bulk manual block",
                duration_seconds=payload.duration_seconds,
                blocked_by=getattr(user, "username", "manual"),
            )
            results.append({"ip": clean_ip, "success": True})
        except Exception as exc:
            results.append(
                {"ip": str(raw_ip), "success": False, "error": str(exc)}
            )
    await crud.create_audit_log(
        db,
        "BULK_BLOCK_IPS",
        user=user,
        target_entity="ip",
        target_id="bulk",
        ip_address=request.client.host if request.client else None,
        detail={
            "requested": len(payload.ips),
            "succeeded": sum(1 for item in results if item["success"]),
        },
    )
    return {"success": any(item["success"] for item in results), "results": results}


@router.post(
    "/networks",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
@limiter.limit("5/minute")
async def block_network(
    request: Request,
    payload: NetworkBlockRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    clean_network = validate_ip_or_network(payload.network)
    if "/" not in clean_network:
        raise HTTPException(status_code=422, detail="CIDR network is required")
    module = _get_ips_module()
    if module is not None and module.is_entry_whitelisted(clean_network):
        raise HTTPException(status_code=403, detail="Network overlaps whitelist")
    if module is not None and not module.block_network(clean_network):
        raise HTTPException(status_code=503, detail="Firewall network block failed")
    await crud.block_ip_db(
        db,
        clean_network,
        reason=payload.reason or "Manual CIDR block",
        duration_seconds=payload.duration_seconds,
        blocked_by=getattr(user, "username", "admin"),
    )
    await crud.create_audit_log(
        db,
        "BLOCK_NETWORK",
        user=user,
        target_entity="network",
        target_id=clean_network,
        ip_address=request.client.host if request.client else None,
    )
    return {"success": True, "network": clean_network}


@router.delete(
    "/networks/{network:path}",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def unblock_network(
    network: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    clean_network = validate_ip_or_network(network)
    module = _get_ips_module()
    if module is not None:
        firewall_ok = module.unblock_network(clean_network)
        if not firewall_ok and bool(getattr(module, "enabled", False)):
            raise HTTPException(
                status_code=503,
                detail="Firewall backend failed to remove the network block",
            )
    if not await crud.unblock_ip_db(db, clean_network):
        raise HTTPException(status_code=404, detail="Network not found")
    await crud.create_audit_log(
        db,
        "UNBLOCK_NETWORK",
        user=user,
        target_entity="network",
        target_id=clean_network,
        ip_address=request.client.host if request.client else None,
    )
    return {"success": True, "network": clean_network}


@router.get("/whitelist", response_model=WhitelistListResponse, dependencies=[Depends(get_current_user)])
async def get_whitelist(_user=Depends(get_current_user)):
    config = get_config()
    whitelist_data = config.get("ips", "whitelist", [])
    whitelist_notes = config.get("ips", "whitelist_notes", {})
    if not isinstance(whitelist_notes, dict):
        whitelist_notes = {}
    items: List[WhitelistItem] = []
    if isinstance(whitelist_data, list):
        if whitelist_data and isinstance(whitelist_data[0], dict):
            items = [WhitelistItem(**{k: v for k, v in w.items() if k in ("ip", "note")}) for w in whitelist_data]
        else:
            items = [
                WhitelistItem(
                    ip=str(w), note=str(whitelist_notes.get(str(w), "") or "")
                )
                for w in whitelist_data
            ]
    return WhitelistListResponse(total=len(items), data=items)


@router.post("/whitelist", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN))])
@limiter.limit("10/minute")
async def add_whitelist(
    request: Request,
    item: WhitelistItem,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN)),
):
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
        # Keep the TOML array homogeneous.  Notes live in a sibling mapping so
        # older installations that expect ``whitelist = ["..."]`` remain valid.
        whitelist.append(clean_entry)
        notes = ips_section.setdefault("whitelist_notes", {})
        if isinstance(notes, dict) and item.note:
            notes[clean_entry] = item.note
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Whitelist configuration is not in expected format.",
        )

    try:
        _persist_whitelist_config(config)
    except Exception:
        whitelist[:] = [
            value
            for value in whitelist
            if (
                str(value.get("ip", ""))
                if isinstance(value, dict)
                else str(value)
            )
            != clean_entry
        ]
        notes = ips_section.get("whitelist_notes", {})
        if isinstance(notes, dict):
            notes.pop(clean_entry, None)
        raise
    ips_module = _get_ips_module()
    if ips_module:
        ips_module.add_to_whitelist(clean_entry)
    await crud.create_audit_log(
        db,
        "ADD_WHITELIST",
        user=_user,
        target_entity="whitelist",
        target_id=clean_entry,
        ip_address=request.client.host if request.client else None,
        detail={"note": item.note},
    )
    return ActionResponse(success=True, message=f"Entry {clean_entry} added to whitelist.")


@router.delete("/whitelist/{ip:path}", response_model=ActionResponse, dependencies=[Depends(require_roles(ROLE_ADMIN))])
async def remove_whitelist(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN)),
):
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

    removed_value = whitelist.pop(found_idx)
    notes = ips_section.setdefault("whitelist_notes", {})
    removed_note = None
    if isinstance(notes, dict):
        removed_note = notes.pop(clean_ip, None)
    try:
        _persist_whitelist_config(config)
    except Exception:
        whitelist.insert(found_idx, removed_value)
        if isinstance(notes, dict) and removed_note is not None:
            notes[clean_ip] = removed_note
        raise
    ips_module = _get_ips_module()
    if ips_module:
        ips_module.remove_from_whitelist(clean_ip)
    await crud.create_audit_log(
        db,
        "REMOVE_WHITELIST",
        user=_user,
        target_entity="whitelist",
        target_id=clean_ip,
        ip_address=request.client.host if request.client else None,
    )
    return ActionResponse(success=True, message=f"Entry {clean_ip} removed from whitelist.")


# Canonical enterprise paths from update.md.  The nested blocked-ips paths stay
# registered for backward compatibility with the existing dashboard/client.
whitelist_router.add_api_route(
    "",
    get_whitelist,
    methods=["GET"],
    response_model=WhitelistListResponse,
)
whitelist_router.add_api_route(
    "",
    add_whitelist,
    methods=["POST"],
    response_model=ActionResponse,
)
whitelist_router.add_api_route(
    "/{ip:path}",
    remove_whitelist,
    methods=["DELETE"],
    response_model=ActionResponse,
)
