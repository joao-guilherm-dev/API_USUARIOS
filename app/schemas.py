import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

Role = Literal["admin", "tecnico", "usuario"]
IMPORT_MAX_USERS = 100

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,50}$")


def _valida_senha(v: str) -> str:
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
        raise ValueError("A senha deve ter pelo menos uma letra e um número")
    return v


class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str = Field(default="", max_length=120)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("Use de 3 a 50 caracteres (letras, números, _ . -)")
        return v.lower()

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.lower()


class UserRegister(UserBase):
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _senha(cls, v: str) -> str:
        return _valida_senha(v)


class UserCreate(UserRegister):
    role: Role = "usuario"


class UserUpdateSelf(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        return v.lower() if v else v


class UserUpdateAdmin(UserUpdateSelf):
    role: Role | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _senha(cls, v: str) -> str:
        return _valida_senha(v)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None
    locked_until: datetime | None


class UserList(BaseModel):
    total: int
    items: list[UserOut]


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TemporaryPassword(BaseModel):
    temporary_password: str


# ------------------------- Exportação / importação JSON ---------------------- #
class UserExport(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class ExportOut(BaseModel):
    exported_at: datetime
    count: int
    users: list[UserExport]


class UserImportItem(UserBase):
    role: Role = "usuario"
    is_active: bool = True
    password: str | None = Field(default=None, min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _senha(cls, v: str | None) -> str | None:
        return _valida_senha(v) if v is not None else v


class ImportRequest(BaseModel):
    users: list[dict[str, Any]] = Field(min_length=1, max_length=IMPORT_MAX_USERS)
    dry_run: bool = False


class ImportCreated(BaseModel):
    index: int
    id: int | None = None
    username: str
    temporary_password: str | None = None


class ImportSkipped(BaseModel):
    index: int
    username: str | None = None
    reason: str


class ImportResult(BaseModel):
    dry_run: bool
    total: int
    created: list[ImportCreated]
    skipped: list[ImportSkipped]
