from fastapi import APIRouter, HTTPException, status

from app.deps import CurrentUser, DbSession, SettingsDep
from app.logging_config import audit
from app.schemas import PasswordChange, UserOut, UserUpdateSelf
from app.security import hash_password, verify_password
from app.services import ensure_unique

router = APIRouter(prefix="/users/me", tags=["perfil"])


@router.get("", response_model=UserOut)
def me(user: CurrentUser):
    return user


@router.patch("", response_model=UserOut)
def update_me(data: UserUpdateSelf, user: CurrentUser, db: DbSession):
    ensure_unique(db, None, data.email, ignore_id=user.id)
    for campo, valor in data.model_dump(exclude_unset=True).items():
        if valor is not None:
            setattr(user, campo, valor)
    db.add(user)
    db.commit()
    audit("profile_updated", user_id=user.id, username=user.username)
    return user


@router.post("/password", status_code=204)
def change_password(data: PasswordChange, user: CurrentUser, db: DbSession, settings: SettingsDep):
    """Troca a própria senha. Invalida todos os tokens existentes (faça login de novo)."""
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Senha atual incorreta")
    user.password_hash = hash_password(data.new_password, settings.pbkdf2_iterations)
    user.token_version += 1
    db.add(user)
    db.commit()
    audit("password_changed", user_id=user.id, username=user.username)
