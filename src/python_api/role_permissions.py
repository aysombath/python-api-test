from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from python_api.auth import require_permission
from python_api.db import get_session
from python_api.models import PermissionDefinition, Role, RolePermission
from python_api.permissions import Permission
from python_api.schemas import PermissionRead, RolePermissionsUpdate

router = APIRouter(
    prefix="/roles",
    tags=["role-permissions"],
    dependencies=[Depends(require_permission(Permission.permissions_manage))],
)


@router.get("/permissions", response_model=list[PermissionRead])
async def list_permissions(
    session: AsyncSession = Depends(get_session),
) -> list[PermissionDefinition]:
    return list((await session.exec(select(PermissionDefinition))).all())


@router.get("/{role}/permissions", response_model=list[str])
async def get_role_permissions(
    role: Role, session: AsyncSession = Depends(get_session)
) -> list[str]:
    result = await session.exec(
        select(PermissionDefinition.key)
        .join(RolePermission, RolePermission.permission_id == PermissionDefinition.id)
        .where(RolePermission.role == role)
    )
    return sorted(result.all())


@router.put("/{role}/permissions", response_model=list[str])
async def set_role_permissions(
    role: Role, body: RolePermissionsUpdate, session: AsyncSession = Depends(get_session)
) -> list[str]:
    if role == Role.sysadmin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="sysadmin permissions are fixed and cannot be changed",
        )

    definitions = (
        await session.exec(
            select(PermissionDefinition).where(
                PermissionDefinition.key.in_(body.permissions)
            )
        )
    ).all()
    found_keys = {d.key for d in definitions}
    missing = set(body.permissions) - found_keys
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown permission keys: {', '.join(sorted(missing))}",
        )

    existing_grants = (
        await session.exec(select(RolePermission).where(RolePermission.role == role))
    ).all()
    for grant in existing_grants:
        await session.delete(grant)
    await session.flush()

    for definition in definitions:
        session.add(RolePermission(role=role, permission_id=definition.id))

    await session.commit()
    return sorted(found_keys)
