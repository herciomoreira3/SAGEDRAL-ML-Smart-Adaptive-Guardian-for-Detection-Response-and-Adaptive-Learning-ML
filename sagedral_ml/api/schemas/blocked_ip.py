"""
Pydantic schemas for Blocked IP API resources.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class BlockIPRequest(BaseModel):
    ip: str = Field(..., min_length=2, max_length=45)
    reason: Optional[str] = Field("Manual block by admin", max_length=1000)
    duration_seconds: Optional[int] = Field(3600, ge=0, le=31536000)


class BlockedIPItem(BaseModel):
    ip: str
    blocked_at: float
    reason: Optional[str] = None
    alert_id: Optional[str] = None
    auto_unblock_at: Optional[float] = None
    blocked_by: Optional[str] = "system"
    is_active: bool = True


class BlockedIPListResponse(BaseModel):
    total: int
    data: List[BlockedIPItem]


class ActionResponse(BaseModel):
    success: bool
    message: str
