"""
Pydantic schemas for Alert API resources.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AlertItem(BaseModel):
    alert_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    final_score: float
    action_taken: str
    signature_matched: List[str] = Field(default_factory=list)
    ml_anomaly_score: Optional[float] = None
    flow_duration: Optional[float] = None
    total_bytes: Optional[int] = None
    src_country: Optional[str] = None
    src_country_code: Optional[str] = None
    status: Optional[str] = "open"
    feedback_label: Optional[str] = None
    feedback_notes: Optional[str] = None
    closed_at: Optional[float] = None


class AlertListResponse(BaseModel):
    total: int
    page: int
    limit: int
    data: List[AlertItem]
