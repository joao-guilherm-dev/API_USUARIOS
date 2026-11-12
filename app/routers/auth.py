from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import or_, select

from app.deps import DbSession, SettingsDep
from app.logging_config import audit
from app.models import User, utcnow
from app.schemas import Token, UserOut, UserRegister
from app.security import (
    DUMMY_HASH,
    create_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.services import ensure_unique

router = APIRouter(prefix="/auth", tags=["auth"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/register", response_model=UserOut, status_code=201)
def register(data: UserRegister, db: DbSession, settings: SettingsDep):
    """Cadastro público. Sempre cria com perfil 'usuario'."""
    ensure_unique(db, data.username, data.email)
    user = User(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        password_hash=hash_password(data.password, settings.pbkdf2_iterations),
        role="usuario",
    )
    db.add(user)
    db.commit()
    audit("user_registered", user_id=user.id, username=user.username)
    return user


@router.post("/login", response_model=Token)
def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    request: Request,
    db: DbSession,
    settings: SettingsDep,
):
    ident = form.username.lower()
    ip = _ip(request)
    user = db.scalar(select(User).where(or_(User.username == ident, User.email == ident)))
    invalido = HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuário ou senha incorretos")

    if not user:
        verify_password(form.password, DUMMY_HASH)  # mesmo tempo de resposta
        audit("login_failed", reason="unknown_user", identifier=ident, ip=ip)
        raise invalido

    now = utcnow()
    if user.locked_until and user.locked_until > now:
        audit("login_blocked", reason="locked", user_id=user.id, username=user.username, ip=ip)
        retry_after = int((user.locked_until - now).total_seconds()) + 1
        raise HTTPException(
            status.HTTP_423_LOCKED,
            f"Conta bloqueada até {user.locked_until:%H:%M} (UTC)",
            headers={"Retry-After": str(retry_after)},
        )

    if not verify_password(form.password, user.password_hash):
        user.failed_attempts += 1
        audit(
            "login_failed",
            reason="bad_password",
            user_id=user.id,
            username=user.username,
            attempts=user.failed_attempts,
            ip=ip,
        )
        if user.failed_attempts >= settings.max_failed_attempts:
            user.locked_until = now + timedelta(minutes=settings.lock_minutes)
            user.failed_attempts = 0
            audit(
                "account_locked",
                user_id=user.id,
                username=user.username,
                minutes=settings.lock_minutes,
                ip=ip,
            )
        db.commit()
        raise invalido

    if not user.is_active:
        audit("login_blocked", reason="inactive", user_id=user.id, username=user.username, ip=ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Conta desativada")

    if needs_rehash(user.password_hash, settings.pbkdf2_iterations):
        user.password_hash = hash_password(form.password, settings.pbkdf2_iterations)
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.commit()
    audit("login_success", user_id=user.id, username=user.username, ip=ip)
    return Token(
        access_token=create_token(user, settings),
        expires_in=settings.token_expire_minutes * 60,
    )
