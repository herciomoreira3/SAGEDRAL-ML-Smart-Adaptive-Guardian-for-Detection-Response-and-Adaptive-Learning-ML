"""
API Router for Custom Signature Rules management.
"""

import re

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.connection import get_db
from sagedral_ml.database import crud
from sagedral_ml.api.schemas.config import RuleCreateRequest, RuleUpdateRequest

from sagedral_ml.api.auth import get_current_user, require_roles, ROLE_ADMIN
from sagedral_ml.api.rate_limit import limiter
from sagedral_ml.core.container import global_container


def _pydantic_dump(model_instance):
    """Compatibility helper: Pydantic v2 uses .model_dump(), v1 uses .dict()."""
    if hasattr(model_instance, "model_dump"):
        return model_instance.model_dump()
    return model_instance.dict()


router = APIRouter(prefix="/api/v1/rules", tags=["Signature Rules"])
RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,49}$")


def _validate_condition(condition_expr: str) -> None:
    engine = global_container.signature_engine
    if engine is None:
        from sagedral_ml.detection.signature_engine import SignatureEngine

        engine = SignatureEngine()
    try:
        engine._compile_safe_condition(condition_expr)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid rule DSL expression: %s" % exc,
        )


@router.get("", dependencies=[Depends(get_current_user)])
async def list_custom_rules(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    rows = await crud.get_all_signature_rules(db)
    return {"total": len(rows), "data": [row.to_dict() for row in rows]}


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_roles(ROLE_ADMIN))])
@limiter.limit("3/minute")
async def create_custom_rule(
    request: Request,
    req: RuleCreateRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    if not RULE_ID_PATTERN.match(req.rule_id):
        raise HTTPException(
            status_code=422,
            detail="rule_id may contain only letters, numbers, '.', '_' and '-'.",
        )
    _validate_condition(req.condition_expr)
    try:
        rule = await crud.create_signature_rule(db, _pydantic_dump(req))
        if global_container.signature_engine is not None:
            await global_container.signature_engine.hot_reload_rules(db)
        await crud.create_audit_log(
            db,
            "CREATE_SIGNATURE_RULE",
            user=user,
            target_entity="signature_rule",
            target_id=rule.rule_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        return {"success": True, "message": f"Rule '{rule.rule_id}' created.", "rule": rule.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create signature rule: {e}",
        )


@router.put(
    "/{rule_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
@limiter.limit("5/minute")
async def update_custom_rule(
    rule_id: str,
    request: Request,
    req: RuleUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    values = _pydantic_dump(req)
    values = {key: value for key, value in values.items() if value is not None}
    if "condition_expr" in values:
        _validate_condition(values["condition_expr"])
    updated = await crud.update_signature_rule(db, rule_id, values)
    if updated is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if global_container.signature_engine is not None:
        await global_container.signature_engine.hot_reload_rules(db)
    await crud.create_audit_log(
        db,
        "UPDATE_SIGNATURE_RULE",
        user=user,
        target_entity="signature_rule",
        target_id=rule_id,
        ip_address=request.client.host if request.client else None,
        detail={"fields": sorted(values.keys())},
    )
    return {"success": True, "rule": updated.to_dict()}


@router.delete(
    "/{rule_id}",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
async def remove_custom_rule(
    rule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_roles(ROLE_ADMIN)),
):
    if not await crud.delete_signature_rule(db, rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    if global_container.signature_engine is not None:
        await global_container.signature_engine.hot_reload_rules(db)
    await crud.create_audit_log(
        db,
        "DELETE_SIGNATURE_RULE",
        user=user,
        target_entity="signature_rule",
        target_id=rule_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"success": True, "rule_id": rule_id}
