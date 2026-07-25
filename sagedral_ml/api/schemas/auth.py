"""
Pydantic schemas for Authentication API resources.
"""

from typing import Optional
from pydantic import BaseModel


class UserProfile(BaseModel):
    id: int
    username: str
    role: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    created_at: Optional[float] = None
    last_login: Optional[float] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile

