"""
API Router for Configuration inspection and update.
"""

from fastapi import APIRouter, HTTPException, status
from sagedral_ml.config import get_config, Config
from sagedral_ml.api.schemas.config import ConfigUpdateRequest

router = APIRouter(prefix="/api/v1/config", tags=["Configuration"])


@router.get("")
async def get_system_config():
    config = get_config()
    return config.to_dict()


@router.put("")
async def update_system_config(req: ConfigUpdateRequest):
    config = get_config()
    new_data = req.config
    
    # Simple validation check
    temp_config = Config(new_data)
    errors = temp_config.validate()
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Configuration validation failed", "errors": errors},
        )

    # Update in-memory dict
    config.data.clear()
    config.data.update(new_data)

    requires_restart = ["capture.interface", "api.port"]

    return {
        "success": True,
        "message": "Configuration updated successfully.",
        "requires_restart": requires_restart,
    }
