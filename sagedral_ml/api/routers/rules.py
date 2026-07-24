"""
API Router for Custom Signature Rules management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.config import RuleCreateRequest

router = APIRouter(prefix="/api/v1/rules", tags=["Signature Rules"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_custom_rule(req: RuleCreateRequest, db: AsyncSession = Depends(get_db)):
    try:
        rule = await crud.create_signature_rule(db, req.model_dump())
        return {"success": True, "message": f"Rule '{rule.rule_id}' created.", "rule": rule.to_dict()}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create signature rule: {e}",
        )
