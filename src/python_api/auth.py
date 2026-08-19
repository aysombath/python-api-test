from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from python_api.config import settings
from python_api.db import get_session
from python_api.models import User
from python_api.permissions import Permission, role_has_permission
from python_api.schemas import RefreshRequest, Token, UserCreate, UserRead
from python_api.security import (
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _issue_tokens(email: str) -> Token:
    return Token(
        access_token=create_access_token(email),
        refresh_token=create_refresh_token(email),
        expires_in=settings.access_token_expire_minutes * 60,
    )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    email = decode_token(token, TokenType.access)
    if email is None:
        raise credentials_error

    user = (await session.exec(select(User).where(User.email == email))).first()
    if user is None or not user.is_active:
        raise credentials_error

    return user


def require_permission(permission: Permission):
    async def dependency(
        current_user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> User:
        if not await role_has_permission(session, current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return current_user

    return dependency


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, session: AsyncSession = Depends(get_session)) -> User:
    existing = (
        await session.exec(select(User).where(User.email == user_in.email))
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    user = User(email=user_in.email, hashed_password=hash_password(user_in.password))
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
) -> Token:
    user = (
        await session.exec(select(User).where(User.email == form_data.username))
    ).first()
    if (
        user is None
        or not user.is_active
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _issue_tokens(user.email)


@router.post("/refresh", response_model=Token)
async def refresh(
    body: RefreshRequest, session: AsyncSession = Depends(get_session)
) -> Token:
    invalid_token_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
    )

    email = decode_token(body.refresh_token, TokenType.refresh)
    if email is None:
        raise invalid_token_error

    user = (await session.exec(select(User).where(User.email == email))).first()
    if user is None or not user.is_active:
        raise invalid_token_error

    return _issue_tokens(user.email)


@router.get("/me", response_model=UserRead)
async def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user
