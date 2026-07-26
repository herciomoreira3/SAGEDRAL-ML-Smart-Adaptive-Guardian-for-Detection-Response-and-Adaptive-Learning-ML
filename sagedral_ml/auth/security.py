"""
Security utilities for SAGEDRAL-ML authentication and authorization.
Handles bcrypt password hashing, JWT token creation/validation,
FastAPI dependency injection for authenticated users with role-based access,
and default admin user database seeding.
"""

import os
import time
import json
import hmac
import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Any, Dict, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from sagedral_ml.config import get_config
from sagedral_ml.database.connection import get_db

logger = logging.getLogger("sagedral_ml.auth.security")

try:
    from jose import JWTError, jwt
    _JOSE_AVAILABLE = True
except Exception:  # pragma: no cover - exercised in minimal/offline envs
    JWTError = ValueError
    jwt = None
    _JOSE_AVAILABLE = False

try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _PASSLIB_AVAILABLE = True
except Exception:  # pragma: no cover - exercised in minimal/offline envs
    pwd_context = None
    _PASSLIB_AVAILABLE = False

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"
VALID_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)

PERMISSION_VIEW = "view"
PERMISSION_EXPORT = "export"
PERMISSION_RESPOND = "respond"
PERMISSION_FEEDBACK = "feedback"
PERMISSION_MANAGE_CONFIG = "manage_config"
PERMISSION_MANAGE_RULES = "manage_rules"
PERMISSION_MANAGE_WHITELIST = "manage_whitelist"
PERMISSION_MANAGE_USERS = "manage_users"
ROLE_PERMISSIONS = {
    ROLE_VIEWER: {PERMISSION_VIEW, PERMISSION_EXPORT},
    ROLE_ANALYST: {
        PERMISSION_VIEW,
        PERMISSION_EXPORT,
        PERMISSION_RESPOND,
        PERMISSION_FEEDBACK,
    },
    ROLE_ADMIN: {
        PERMISSION_VIEW,
        PERMISSION_EXPORT,
        PERMISSION_RESPOND,
        PERMISSION_FEEDBACK,
        PERMISSION_MANAGE_CONFIG,
        PERMISSION_MANAGE_RULES,
        PERMISSION_MANAGE_WHITELIST,
        PERMISSION_MANAGE_USERS,
    },
}

_generated_secret_cache: Optional[str] = None
_FALLBACK_HASH_PREFIX = "pbkdf2_sha256"
_FALLBACK_HASH_ROUNDS = 210_000


class TokenData(BaseModel):
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None


class UserProfile(BaseModel):
    id: int
    username: str
    role: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    is_active: bool = True
    created_at: Optional[float] = None
    last_login: Optional[float] = None


def get_jwt_secret_key() -> str:
    global _generated_secret_cache
    config = get_config()
    secret_key = config.get("auth", "secret_key", "")
    if secret_key and isinstance(secret_key, str) and len(secret_key.strip()) >= 32:
        return secret_key.strip()

    if _generated_secret_cache:
        return _generated_secret_cache

    data_dir = str(
        config.get("general", "data_dir", "/var/lib/sagedral-ml") or "."
    )
    secret_path = str(
        config.get("auth", "jwt_secret_file", "")
        or os.path.join(data_dir, ".sagedral-jwt-secret")
    )
    try:
        if os.path.exists(secret_path):
            with open(secret_path, "r", encoding="utf-8") as handle:
                persisted = handle.read().strip()
            if len(persisted) >= 32:
                _generated_secret_cache = persisted
                return persisted
            logger.warning(
                "JWT secret file %s is too short; replacing it securely.",
                secret_path,
            )
        secret_dir = os.path.dirname(secret_path)
        if secret_dir:
            os.makedirs(secret_dir, exist_ok=True)
        lock_path = secret_path + ".lock"
        lock_descriptor = None
        for _attempt in range(100):
            try:
                lock_descriptor = os.open(
                    lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.close(lock_descriptor)
                lock_descriptor = None
                break
            except FileExistsError:
                try:
                    with open(secret_path, "r", encoding="utf-8") as handle:
                        candidate = handle.read().strip()
                    if len(candidate) >= 32:
                        _generated_secret_cache = candidate
                        return candidate
                except OSError:
                    pass
                time.sleep(0.05)
        else:
            raise RuntimeError("timed out waiting for JWT secret file lock")

        generated = secrets.token_urlsafe(64)
        temporary_path = secret_path + ".tmp-%s-%s" % (
            os.getpid(),
            secrets.token_hex(4),
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(temporary_path, flags, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(generated)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_path, secret_path)
                try:
                    os.chmod(secret_path, 0o600)
                except OSError:
                    pass
            finally:
                try:
                    if os.path.exists(temporary_path):
                        os.unlink(temporary_path)
                except OSError:
                    pass
        finally:
            try:
                os.unlink(lock_path)
            except OSError:
                pass
        _generated_secret_cache = generated
        logger.warning(
            "[auth] secret_key config kosong; generated persistent JWT secret at %s",
            secret_path,
        )
    except FileExistsError:
        with open(secret_path, "r", encoding="utf-8") as handle:
            candidate = handle.read().strip()
        _generated_secret_cache = (
            candidate if len(candidate) >= 32 else secrets.token_urlsafe(64)
        )
    except Exception as exc:
        logger.critical(
            "Tidak dapat mempersist JWT secret ke %s (%s); memakai secret sesi.",
            secret_path,
            exc,
        )
        _generated_secret_cache = secrets.token_urlsafe(64)
    return _generated_secret_cache


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def get_jwt_algorithm() -> str:
    config = get_config()
    algo = config.get("auth", "algorithm", "HS256")
    if algo not in ("HS256", "HS384", "HS512"):
        return "HS256"
    return algo


def get_access_token_expire_minutes() -> int:
    config = get_config()
    try:
        minutes = int(config.get("auth", "access_token_expire_minutes", 1440))
        if minutes <= 0:
            return 1440
        return minutes
    except (ValueError, TypeError):
        return 1440


def hash_password(password: str) -> str:
    if _PASSLIB_AVAILABLE and pwd_context is not None:
        return pwd_context.hash(password)

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _FALLBACK_HASH_ROUNDS,
    )
    return "$".join(
        [
            _FALLBACK_HASH_PREFIX,
            str(_FALLBACK_HASH_ROUNDS),
            _b64url_encode(salt),
            _b64url_encode(digest),
        ]
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if _PASSLIB_AVAILABLE and pwd_context is not None:
            return pwd_context.verify(plain_password, hashed_password)

        parts = (hashed_password or "").split("$")
        if len(parts) != 4 or parts[0] != _FALLBACK_HASH_PREFIX:
            logger.warning(
                "passlib tidak tersedia dan password hash bukan format fallback; "
                "install passlib[bcrypt] untuk memverifikasi hash bcrypt."
            )
            return False

        rounds = int(parts[1])
        salt = _b64url_decode(parts[2])
        expected = _b64url_decode(parts[3])
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            rounds,
        )
        return hmac.compare_digest(actual, expected)
    except Exception as e:
        logger.warning(f"verify_password error: {e}")
        return False


def _normalise_claims_for_json(claims: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in claims.items():
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            normalized[key] = int(value.timestamp())
        else:
            normalized[key] = value
    return normalized


def create_access_token(
    subject: Union[str, int],
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    to_encode: Dict[str, Any] = {}
    if extra_claims:
        to_encode.update(extra_claims)

    if expires_delta is None:
        expire_minutes = get_access_token_expire_minutes()
        expire = datetime.utcnow() + timedelta(minutes=expire_minutes)
    else:
        expire = datetime.utcnow() + expires_delta

    to_encode.update(
        {
            "sub": str(subject),
            "username": username,
            "role": role,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
        }
    )

    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()
    if _JOSE_AVAILABLE and jwt is not None:
        return jwt.encode(to_encode, secret_key, algorithm=algorithm)

    header = {"typ": "JWT", "alg": "HS256"}
    payload = _normalise_claims_for_json(to_encode)
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode_access_token(token: str) -> Dict[str, Any]:
    secret_key = get_jwt_secret_key()
    algorithm = get_jwt_algorithm()
    if _JOSE_AVAILABLE and jwt is not None:
        return jwt.decode(token, secret_key, algorithms=[algorithm])

    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(signature_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("invalid token signature")

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        exp = payload.get("exp")
        if exp is not None and float(exp) < time.time():
            raise ValueError("token expired")
        if payload.get("type") != "access":
            raise ValueError("invalid token type")
        return payload
    except Exception as exc:
        raise JWTError(str(exc))


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Any:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Tidak dapat memverifikasi kredensial. Silakan login kembali.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    try:
        payload = decode_access_token(token)

        user_id_str: Optional[str] = payload.get("sub")
        username: Optional[str] = payload.get("username")
        role: Optional[str] = payload.get("role")

        if user_id_str is None or username is None:
            raise credentials_exception

        token_data = TokenData(user_id=int(user_id_str), username=username, role=role)
    except JWTError:
        raise credentials_exception
    except (ValueError, TypeError):
        raise credentials_exception

    try:
        from sagedral_ml.database.models import UserModel

        stmt = select(UserModel).where(UserModel.id == token_data.user_id)
        res = await db.execute(stmt)
        user = res.scalar_one_or_none()

        if user is None:
            raise credentials_exception
        if not bool(getattr(user, "is_active", 1)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Akun user sudah dinonaktifkan.",
            )
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_current_user lookup error: {e}")
        raise credentials_exception


def require_roles(*roles: str):
    allowed = [r for r in roles if r in VALID_ROLES] or list(VALID_ROLES)

    async def _check_role(user: Any = Depends(get_current_user)) -> Any:
        user_role = getattr(user, "role", ROLE_VIEWER) or ROLE_VIEWER
        if user_role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Akses ditolak. Dibutuhkan role salah satu: {', '.join(allowed)}. Role Anda: {user_role}",
            )
        return user

    return _check_role


def require_permission(permission: str):
    """FastAPI dependency for stable per-action authorization."""
    async def _check_permission(user: Any = Depends(get_current_user)) -> Any:
        role = getattr(user, "role", ROLE_VIEWER) or ROLE_VIEWER
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Akses ditolak untuk aksi '%s'." % permission,
            )
        return user

    return _check_permission


async def seed_default_admin(db: AsyncSession) -> bool:
    from sagedral_ml.database.models import UserModel

    config = get_config()
    admin_username = config.get("auth", "default_admin_username", "admin") or "admin"
    admin_password = config.get("auth", "default_admin_password", "") or ""
    admin_email = config.get("auth", "default_admin_email", "admin@sagedral.local") or "admin@sagedral.local"

    try:
        stmt = select(UserModel).where(UserModel.username == admin_username)
        res = await db.execute(stmt)
        existing = res.scalar_one_or_none()

        if existing is not None:
            logger.info(f"Admin user '{admin_username}' sudah ada. Skip seeding.")
            return False

        generated_password = False
        if not admin_password or admin_password in {"admin", "admin123", "sagedral-admin-2024"}:
            admin_password = secrets.token_urlsafe(18)
            generated_password = True

        now = time.time()
        admin = UserModel(
            username=admin_username,
            password_hash=hash_password(admin_password),
            role=ROLE_ADMIN,
            full_name="System Administrator",
            email=admin_email,
            is_active=1,
            created_at=now,
            last_login=None,
        )
        db.add(admin)
        await db.commit()
        await db.refresh(admin)

        if generated_password:
            secret_file = (
                config.get("auth", "admin_secret_file", "")
                or os.path.join(config.get("general", "data_dir", "/var/lib/sagedral-ml"), ".sagedral-admin-secret")
            )
            try:
                secret_dir = os.path.dirname(secret_file)
                if secret_dir:
                    os.makedirs(secret_dir, exist_ok=True)
                output_secret_file = secret_file
                try:
                    descriptor = os.open(
                        output_secret_file,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                except FileExistsError:
                    output_secret_file = "%s.new-%d" % (
                        secret_file,
                        int(time.time()),
                    )
                    descriptor = os.open(
                        output_secret_file,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                with os.fdopen(descriptor, "w", encoding="utf-8") as f:
                    f.write(
                        "username=%s\npassword=%s\n"
                        % (admin_username, admin_password)
                    )
                try:
                    os.chmod(output_secret_file, 0o600)
                except Exception:
                    pass
                logger.warning(
                    f"Generated first admin password for '{admin_username}'. "
                    f"Secret saved to {output_secret_file} (chmod 600 when supported)."
                )
            except Exception as e:
                logger.critical(
                    "Generated first admin password for '%s' but failed to "
                    "write the secret file: %s. Disable the account or reset "
                    "its password from an offline administrative session.",
                    admin_username,
                    e,
                )
                try:
                    await db.delete(admin)
                    await db.commit()
                except Exception:
                    await db.rollback()
                return False

        logger.info(
            f"Default admin user seeded: username='{admin_username}' role='{ROLE_ADMIN}'. "
            "SEGERA GANTI PASSWORD SETELAH LOGIN PERTAMA!"
        )
        return True
    except Exception as e:
        await db.rollback()
        logger.error(f"Gagal seed default admin user: {e}")
        return False
