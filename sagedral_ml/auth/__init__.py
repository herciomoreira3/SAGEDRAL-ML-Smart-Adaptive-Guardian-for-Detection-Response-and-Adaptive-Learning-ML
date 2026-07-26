"""
Authentication and authorization package for SAGEDRAL-ML.
Provides password hashing, JWT token management, user role-based access control,
and default admin user seeding.
"""

from sagedral_ml.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    require_roles,
    seed_default_admin,
    get_jwt_secret_key,
    require_permission,
)

__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "get_current_user",
    "require_roles",
    "seed_default_admin",
    "get_jwt_secret_key",
    "require_permission",
]
