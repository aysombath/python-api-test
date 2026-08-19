from pydantic import BaseModel, EmailStr

from python_api.models import Role


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserCreateAdmin(BaseModel):
    email: EmailStr
    password: str
    role: Role = Role.user


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    is_active: bool | None = None
    role: Role | None = None


class RoleAssign(BaseModel):
    role: Role


class UserRead(BaseModel):
    id: int
    email: EmailStr
    is_active: bool
    role: Role


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class PermissionRead(BaseModel):
    id: int
    key: str
    description: str | None = None


class RolePermissionsUpdate(BaseModel):
    permissions: list[str]
