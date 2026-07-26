"""
Pydantic schemas for Config and Signature Rule API endpoints.
"""

from typing import Dict, Any, Literal, Optional
from pydantic import BaseModel, Field


class ConfigUpdateRequest(BaseModel):
    config: Dict[str, Any]


class RuleCreateRequest(BaseModel):
    rule_id: str = Field(..., min_length=3, max_length=50)
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field("", max_length=2000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    condition_expr: str = Field(..., min_length=1, max_length=1000)
    attack_type: str = Field(..., min_length=1, max_length=50)


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=2000)
    severity: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = None
    condition_expr: Optional[str] = Field(None, min_length=1, max_length=1000)
    attack_type: Optional[str] = Field(None, min_length=1, max_length=50)
    is_enabled: Optional[bool] = None
