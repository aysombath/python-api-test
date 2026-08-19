from enum import Enum

from sqlalchemy import Column, String, UniqueConstraint
from sqlmodel import Field, SQLModel


class Role(str, Enum):
    sysadmin = "sysadmin"
    admin = "admin"
    user = "user"


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    role: Role = Field(default=Role.user, sa_column=Column(String, nullable=False))


class PermissionDefinition(SQLModel, table=True):
    __tablename__ = "permission"

    id: int | None = Field(default=None, primary_key=True)
    key: str = Field(unique=True, index=True)
    description: str | None = None


class RolePermission(SQLModel, table=True):
    __tablename__ = "role_permission"
    __table_args__ = (UniqueConstraint("role", "permission_id", name="uq_role_permission"),)

    id: int | None = Field(default=None, primary_key=True)
    role: Role = Field(sa_column=Column(String, nullable=False))
    permission_id: int = Field(foreign_key="permission.id")
