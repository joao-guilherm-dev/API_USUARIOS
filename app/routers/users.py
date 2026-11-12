import secrets
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import func, or_, select

from app.deps import AdminUser, CurrentUser, DbSession, SettingsDep, StaffUser
from app.errors import clean_error_message
from app.logging_config import audit
from app.models import User, utcnow
from app.schemas import (
    ExportOut,
    ImportCreated,
    ImportRequest,
    ImportResult,
    ImportSkipped,
    Role,
    TemporaryPassword,
    UserCreate,
    UserExport,
    UserImportItem,
    UserList,
    UserOut,
    UserUpdateAdmin,
)
from app.security import hash_password
from app.services import ensure_unique, find_conflict

router = APIRouter(prefix="/users", tags=["admin"])

NOT_FOUND = "Usuário não encontrado"


def _get_or_404(db, user_id: int) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    return user


@router.get("", response_model=UserList)
def list_users(
    _: StaffUser,
    db: DbSession,
    q: Annotated[str | None, Query(description="Busca em username, e-mail e nome")] = None,
    role: Role | None = None,
    is_active: bool | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(User.username).like(like),
                func.lower(User.email).like(like),
                func.lower(User.full_name).like(like),
            )
        )
    if role:
        stmt = stmt.where(User.role == role)
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    items = db.scalars(stmt.order_by(User.id).offset(skip).limit(limit)).all()
    return UserList(total=total, items=items)


# /export e /import vêm antes de /{user_id} para não serem capturadas pela rota dinâmica.
@router.get("/export", response_model=ExportOut)
def export_users(admin: AdminUser, db: DbSession):
    """Exporta todos os usuários em JSON (sem senhas). O arquivo pode ser reimportado."""
    users = db.scalars(select(User).order_by(User.id)).all()
    payload = ExportOut(
        exported_at=utcnow(),
        count=len(users),
        users=[UserExport.model_validate(u) for u in users],
    )
    audit("users_exported", actor_id=admin.id, actor=admin.username, count=len(users))
    return JSONResponse(
        content=jsonable_encoder(payload),
        headers={"Content-Disposition": 'attachment; filename="usuarios.json"'},
    )


@router.post("/import", response_model=ImportResult)
def import_users(data: ImportRequest, admin: AdminUser, db: DbSession, settings: SettingsDep):
    """Importa usuários de um JSON. Cada item é validado separadamente: os inválidos ou
    duplicados são reportados em `skipped` e os demais são criados. Sem `password`, gera-se
    uma senha temporária (devolvida uma única vez). Use `dry_run` para só simular."""
    created: list[ImportCreated] = []
    skipped: list[ImportSkipped] = []
    seen_usernames: set[str] = set()
    seen_emails: set[str] = set()

    for index, raw in enumerate(data.users):
        raw_username = raw.get("username") if isinstance(raw.get("username"), str) else None
        try:
            item = UserImportItem.model_validate(raw)
        except ValidationError as exc:
            first = exc.errors()[0]
            campo = ".".join(str(p) for p in first["loc"])
            reason = f"{campo}: {clean_error_message(first['msg'])}"
            skipped.append(ImportSkipped(index=index, username=raw_username, reason=reason))
            continue

        if item.username in seen_usernames or item.email in seen_emails:
            skipped.append(
                ImportSkipped(index=index, username=item.username, reason="duplicado no arquivo")
            )
            continue
        conflito = find_conflict(db, item.username, item.email)
        if conflito:
            skipped.append(
                ImportSkipped(
                    index=index,
                    username=item.username,
                    reason=f"já existe um usuário com este {conflito}",
                )
            )
            continue

        seen_usernames.add(item.username)
        seen_emails.add(item.email)
        if data.dry_run:
            created.append(ImportCreated(index=index, username=item.username))
            continue

        temp = None if item.password else secrets.token_urlsafe(10)
        user = User(
            username=item.username,
            email=item.email,
            full_name=item.full_name,
            role=item.role,
            is_active=item.is_active,
            password_hash=hash_password(item.password or temp, settings.pbkdf2_iterations),
        )
        db.add(user)
        db.flush()
        created.append(
            ImportCreated(index=index, id=user.id, username=user.username, temporary_password=temp)
        )

    if not data.dry_run:
        db.commit()
    audit(
        "users_imported",
        actor_id=admin.id,
        actor=admin.username,
        dry_run=data.dry_run,
        created=len(created),
        skipped=len(skipped),
    )
    return ImportResult(
        dry_run=data.dry_run, total=len(data.users), created=created, skipped=skipped
    )


@router.post("", response_model=UserOut, status_code=201)
def create_user(data: UserCreate, admin: AdminUser, db: DbSession, settings: SettingsDep):
    ensure_unique(db, data.username, data.email)
    user = User(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        password_hash=hash_password(data.password, settings.pbkdf2_iterations),
        role=data.role,
    )
    db.add(user)
    db.commit()
    audit("user_created", actor_id=admin.id, actor=admin.username, user_id=user.id, role=user.role)
    return user


@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: int, current: CurrentUser, db: DbSession):
    if current.role == "usuario" and current.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para esta ação")
    return _get_or_404(db, user_id)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, data: UserUpdateAdmin, current: AdminUser, db: DbSession):
    user = _get_or_404(db, user_id)
    if user.id == current.id and (data.role not in (None, "admin") or data.is_active is False):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Você não pode rebaixar ou desativar a própria conta"
        )
    ensure_unique(db, None, data.email, ignore_id=user.id)
    changes = {k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None}
    for campo, valor in changes.items():
        setattr(user, campo, valor)
    db.add(user)
    db.commit()
    audit(
        "user_updated",
        actor_id=current.id,
        actor=current.username,
        user_id=user.id,
        fields=sorted(changes),
    )
    return user


@router.post("/{user_id}/reset-password", response_model=TemporaryPassword)
def reset_password(user_id: int, admin: AdminUser, db: DbSession, settings: SettingsDep):
    user = _get_or_404(db, user_id)
    temp = secrets.token_urlsafe(10)
    user.password_hash = hash_password(temp, settings.pbkdf2_iterations)
    user.token_version += 1
    db.add(user)
    db.commit()
    audit("password_reset", actor_id=admin.id, actor=admin.username, user_id=user.id)
    return TemporaryPassword(temporary_password=temp)


@router.post("/{user_id}/unlock", response_model=UserOut)
def unlock_user(user_id: int, admin: AdminUser, db: DbSession):
    user = _get_or_404(db, user_id)
    user.failed_attempts = 0
    user.locked_until = None
    db.add(user)
    db.commit()
    audit("user_unlocked", actor_id=admin.id, actor=admin.username, user_id=user.id)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, admin: AdminUser, db: DbSession):
    if user_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Você não pode excluir a própria conta")
    user = _get_or_404(db, user_id)
    db.delete(user)
    db.commit()
    audit("user_deleted", actor_id=admin.id, actor=admin.username, user_id=user_id)
