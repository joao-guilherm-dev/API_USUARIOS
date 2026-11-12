from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import User


def find_conflict(
    db: Session, username: str | None, email: str | None, ignore_id: int | None = None
) -> str | None:
    """Retorna "username" ou "e-mail" se já existir outro usuário com o valor; senão None."""
    conds = []
    if username:
        conds.append(User.username == username)
    if email:
        conds.append(User.email == email)
    if not conds:
        return None
    stmt = select(User).where(or_(*conds))
    if ignore_id:
        stmt = stmt.where(User.id != ignore_id)
    existente = db.scalar(stmt)
    if not existente:
        return None
    return "username" if username and existente.username == username else "e-mail"


def ensure_unique(
    db: Session, username: str | None, email: str | None, ignore_id: int | None = None
) -> None:
    campo = find_conflict(db, username, email, ignore_id)
    if campo:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Já existe um usuário com este {campo}")
