"""
FastAPI auth dependency re-exports.

Routers import from ``sagedral_ml.api.auth`` so authentication stays decoupled
from the internal ``sagedral_ml.auth.security`` implementation module.
"""

from sagedral_ml.auth.security import (
    get_current_user,
    require_roles,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    VALID_ROLES,
    require_permission,
    ROLE_PERMISSIONS,
    PERMISSION_VIEW,
    PERMISSION_EXPORT,
    PERMISSION_RESPOND,
    PERMISSION_FEEDBACK,
    PERMISSION_MANAGE_CONFIG,
    PERMISSION_MANAGE_RULES,
    PERMISSION_MANAGE_WHITELIST,
    PERMISSION_MANAGE_USERS,
)

__all__ = [
    "get_current_user",
    "require_roles",
    "ROLE_ADMIN",
    "ROLE_ANALYST",
    "ROLE_VIEWER",
    "VALID_ROLES",
    "require_permission",
    "ROLE_PERMISSIONS",
    "PERMISSION_VIEW",
    "PERMISSION_EXPORT",
    "PERMISSION_RESPOND",
    "PERMISSION_FEEDBACK",
    "PERMISSION_MANAGE_CONFIG",
    "PERMISSION_MANAGE_RULES",
    "PERMISSION_MANAGE_WHITELIST",
    "PERMISSION_MANAGE_USERS",
]
