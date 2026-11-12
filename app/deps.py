from collections.abc import Iterator
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User
from app.security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], db: DbSession, settings: SettingsDep
) -> User:
    erro = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token, settings)
        user_id = int(payload["sub"])
        version = int(payload.get("ver", 0))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise erro from None
    user = db.get(User, user_id)
    if not user or not user.is_active or user.token_version != version:
        raise erro
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: str):
    def checker(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para esta ação")
        return user

    return checker


AdminUser = Annotated[User, Depends(require_roles("admin"))]
StaffUser = Annotated[User, Depends(require_roles("admin", "tecnico"))]
