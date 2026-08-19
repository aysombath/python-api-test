from datetime import UTC, datetime, timedelta
from enum import Enum

import bcrypt
from jose import JWTError, jwt

from python_api.config import settings


class TokenType(str, Enum):
    access = "access"
    refresh = "refresh"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def _create_token(subject: str, token_type: TokenType, expires_delta: timedelta) -> str:
    expire = datetime.now(UTC) + expires_delta
    payload = {"sub": subject, "type": token_type.value, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(subject: str) -> str:
    return _create_token(
        subject, TokenType.access, timedelta(minutes=settings.access_token_expire_minutes)
    )


def create_refresh_token(subject: str) -> str:
    return _create_token(
        subject, TokenType.refresh, timedelta(days=settings.refresh_token_expire_days)
    )


def decode_token(token: str, expected_type: TokenType) -> str | None:
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except JWTError:
        return None

    if payload.get("type") != expected_type.value:
        return None

    return payload.get("sub")
