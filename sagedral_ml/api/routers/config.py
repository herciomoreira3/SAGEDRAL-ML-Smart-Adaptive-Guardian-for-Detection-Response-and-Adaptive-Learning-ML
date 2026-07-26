"""
API Router for Configuration inspection and update.
"""

import copy

from fastapi import APIRouter, HTTPException, status, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.config import get_config, Config
from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.config import ConfigUpdateRequest
from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ADMIN
from sagedral_ml.api.rate_limit import limiter

router = APIRouter(prefix="/api/v1/config", tags=["Configuration"])


@router.get("", dependencies=[Depends(get_current_user)])
async def get_system_config(_user=Depends(get_current_user)):
    config = get_config()
    return config.to_safe_dict()


@router.put("", dependencies=[Depends(require_roles(ROLE_ADMIN))])
@limiter.limit("5/minute")
async def update_system_config(
    request: Request,
    req: ConfigUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    config = get_config()
    old_data = copy.deepcopy(config.to_dict())
    new_data = copy.deepcopy(old_data)
    requested_data = copy.deepcopy(req.config)

    # Masked values returned by GET /config mean "keep the current secret".
    for dotted_key in config.sensitive_keys:
        section, key = dotted_key.split(".", 1)
        requested_section = requested_data.get(section)
        if (
            isinstance(requested_section, dict)
            and requested_section.get(key) == "********"
        ):
            requested_section[key] = old_data.get(section, {}).get(key, "")

    def _merge(base, update):
        for key, value in update.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                _merge(base[key], value)
            else:
                base[key] = value

    # Partial updates are supported and never erase configuration added by a
    # newer release.
    _merge(new_data, requested_data)

    temp_config = Config(new_data)
    errors = temp_config.validate()
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Configuration validation failed", "errors": errors},
        )

    requires_restart = config.get_changed_restart_keys(new_data)

    config.data.clear()
    config.data.update(new_data)

    save_ok = config.save()
    if not save_ok:
        config.data.clear()
        config.data.update(old_data)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist configuration to TOML file. Changes were rolled back in memory.",
        )

    changes = {}
    for key, new_val in temp_config._flatten_dict(new_data).items():
        old_val = temp_config._flatten_dict(old_data).get(key)
        if old_val != new_val:
            changes[key] = (old_val, new_val)

    if changes:
        username = getattr(user, "username", "admin") if user else "admin"
        history_changes = {}
        sensitive = set(config.sensitive_keys)
        for key, values in changes.items():
            history_changes[key] = (
                ("********", "********") if key in sensitive else values
            )
        await crud.create_config_history_entries(
            db, history_changes, changed_by=username
        )
        await crud.create_audit_log(
            db,
            "UPDATE_CONFIG",
            user=user,
            target_entity="config",
            target_id="system",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            detail={"changed_keys": sorted(changes.keys())},
        )

    return {
        "success": True,
        "message": "Configuration updated and saved to TOML successfully.",
        "requires_restart": requires_restart,
        "saved_to_disk": save_ok,
    }
