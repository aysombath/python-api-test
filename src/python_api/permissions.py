from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from python_api.models import PermissionDefinition, Role, RolePermission


class Permission(str, Enum):
    users_read = "users:read"
    users_write = "users:write"
    users_delete = "users:delete"
    roles_assign = "roles:assign"
    permissions_manage = "permissions:manage"


# Seeded into the role_permission table on first startup only; after that,
# grants are owned by the DB and editable via the /roles/{role}/permissions API.
DEFAULT_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.sysadmin: {
        Permission.users_read,
        Permission.users_write,
        Permission.users_delete,
        Permission.roles_assign,
        Permission.permissions_manage,
    },
    Role.admin: {
        Permission.users_read,
        Permission.users_write,
    },
    Role.user: set(),
}


async def role_has_permission(session: AsyncSession, role: Role, permission: Permission) -> bool:
    result = await session.exec(
        select(RolePermission)
        .join(PermissionDefinition, RolePermission.permission_id == PermissionDefinition.id)
        .where(RolePermission.role == role, PermissionDefinition.key == permission.value)
    )
    return result.first() is not None
