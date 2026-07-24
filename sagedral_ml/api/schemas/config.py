"""
Pydantic schemas for Config and Signature Rule API endpoints.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel


class ConfigUpdateRequest(BaseModel):
    config: Dict[str, Any]


class RuleCreateRequest(BaseModel):
    rule_id: str
    name: str
    description: Optional[str] = ""
    severity: str
    condition_expr: str
    attack_type: str
