"""
API Router for Custom Signature Rules management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.config import RuleCreateRequest

from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ADMIN


def _pydantic_dump(model_instance):
    """Compatibility helper: Pydantic v2 uses .model_dump(), v1 uses .dict()."""
    if hasattr(model_instance, "model_dump"):
        return model_instance.model_dump()
    return model_instance.dict()


router = APIRouter(prefix="/api/v1/rules", tags=["Signature Rules"])


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_roles(ROLE_ADMIN))])
async def create_custom_rule(
    req: RuleCreateRequest,
    db: AsyncSession = Depends(get_db),
    _user=Depends(require_roles(ROLE_ADMIN)),
):
    try:
        rule = await crud.create_signature_rule(db, _pydantic_dump(req))
        return {"success": True, "message": f"Rule '{rule.rule_id}' created.", "rule": rule.to_dict()}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create signature rule: {e}",
        )
