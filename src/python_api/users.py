from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from python_api.auth import get_current_user, require_permission
from python_api.db import get_session
from python_api.models import Role, User
from python_api.permissions import Permission, role_has_permission
from python_api.schemas import RoleAssign, UserCreateAdmin, UserRead, UserUpdate
from python_api.security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


def _forbid_if_targets_sysadmin(actor: User, target: User) -> None:
    if target.role == Role.sysadmin and actor.role != Role.sysadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify a sysadmin account"
        )


@router.get(
    "",
    response_model=list[UserRead],
    dependencies=[Depends(require_permission(Permission.users_read))],
)
async def list_users(session: AsyncSession = Depends(get_session)) -> list[User]:
    return list((await session.exec(select(User))).all())


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreateAdmin,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(Permission.users_write)),
) -> User:
    if user_in.role != Role.user and not await role_has_permission(
        session, current_user.role, Permission.roles_assign
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to assign this role",
        )

    existing = (
        await session.exec(select(User).where(User.email == user_in.email))
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    user = User(
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=user_in.role,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_permission(Permission.users_write)),
) -> User:
    if user_in.role is not None and not await role_has_permission(
        session, current_user.role, Permission.roles_assign
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to assign roles",
        )

    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    _forbid_if_targets_sysadmin(current_user, user)

    if user_in.email is not None:
        user.email = user_in.email
    if user_in.password is not None:
        user.hashed_password = hash_password(user_in.password)
    if user_in.is_active is not None:
        user.is_active = user_in.is_active
    if user_in.role is not None:
        user.role = user_in.role

    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(Permission.users_delete))],
)
async def delete_user(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> None:
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account"
        )

    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    _forbid_if_targets_sysadmin(current_user, user)

    await session.delete(user)
    await session.commit()


@router.patch(
    "/{user_id}/role",
    response_model=UserRead,
    dependencies=[Depends(require_permission(Permission.roles_assign))],
)
async def assign_role(
    user_id: int, role_in: RoleAssign, session: AsyncSession = Depends(get_session)
) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.role = role_in.role
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
