from sqlmodel import select

from python_api.config import settings
from python_api.db import async_session_maker
from python_api.models import PermissionDefinition, Role, RolePermission, User
from python_api.permissions import DEFAULT_ROLE_PERMISSIONS, Permission
from python_api.security import hash_password


async def seed_permissions() -> None:
    async with async_session_maker() as session:
        key_to_id: dict[str, int] = {}
        for permission in Permission:
            existing = (
                await session.exec(
                    select(PermissionDefinition).where(
                        PermissionDefinition.key == permission.value
                    )
                )
            ).first()
            if existing is None:
                existing = PermissionDefinition(key=permission.value)
                session.add(existing)
                await session.commit()
                await session.refresh(existing)
            key_to_id[permission.value] = existing.id

        # Default grants are only seeded once, on a fresh table. After that,
        # role -> permission mappings are owned by the DB and left alone here
        # so edits made through the API survive restarts.
        any_grant = (await session.exec(select(RolePermission))).first()
        if any_grant is not None:
            return

        for role, permissions in DEFAULT_ROLE_PERMISSIONS.items():
            for permission in permissions:
                session.add(
                    RolePermission(role=role, permission_id=key_to_id[permission.value])
                )
        await session.commit()


async def seed_sysadmin() -> None:
    if not settings.sysadmin_email or not settings.sysadmin_password:
        return

    async with async_session_maker() as session:
        existing = (
            await session.exec(select(User).where(User.email == settings.sysadmin_email))
        ).first()
        if existing is not None:
            if existing.role != Role.sysadmin:
                existing.role = Role.sysadmin
                session.add(existing)
                await session.commit()
            return

        user = User(
            email=settings.sysadmin_email,
            hashed_password=hash_password(settings.sysadmin_password),
            role=Role.sysadmin,
        )
        session.add(user)
        await session.commit()
