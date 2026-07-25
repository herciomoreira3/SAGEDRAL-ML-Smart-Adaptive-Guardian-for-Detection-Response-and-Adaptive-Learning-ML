"""
API Router for Configuration inspection and update.
"""

import copy

from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.config import get_config, Config
from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.config import ConfigUpdateRequest
from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ADMIN

router = APIRouter(prefix="/api/v1/config", tags=["Configuration"])


@router.get("", dependencies=[Depends(get_current_user)])
async def get_system_config(_user=Depends(get_current_user)):
    config = get_config()
    return config.to_dict()


@router.put("", dependencies=[Depends(require_roles(ROLE_ADMIN))])
async def update_system_config(
    req: ConfigUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    config = get_config()
    old_data = copy.deepcopy(config.to_dict())
    new_data = req.config

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
        await crud.create_config_history_entries(db, changes, changed_by=username)

    return {
        "success": True,
        "message": "Configuration updated and saved to TOML successfully.",
        "requires_restart": requires_restart,
        "saved_to_disk": save_ok,
    }
