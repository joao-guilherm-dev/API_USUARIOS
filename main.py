import hashlib
import hmac
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, func, or_, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./usuarios.db")
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
if not os.getenv("SECRET_KEY"):
    print("[aviso] SECRET_KEY não definida: gerada aleatoriamente "
          "(os tokens deixam de valer quando a API reiniciar).")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))
MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
LOCK_MINUTES = int(os.getenv("LOCK_MINUTES", "15"))
PBKDF2_ITERATIONS = 200_000

ROLES = ("admin", "tecnico", "usuario")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="usuario")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
        new = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(new.hex(), digest)
    except (ValueError, TypeError):
        return False


def create_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "exp": utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    erro = HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido ou expirado",
                         headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise erro
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise erro
    return user


def require_roles(*roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para esta ação")
        return user
    return checker


require_admin = require_roles("admin")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,50}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valida_senha(v: str) -> str:
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
        raise ValueError("A senha deve ter pelo menos uma letra e um número")
    return v


class UserBase(BaseModel):
    username: str
    email: str
    full_name: str = Field(default="", max_length=120)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("username: 3-50 caracteres (letras, números, _ . -)")
        return v.lower()

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError("e-mail inválido")
        return v.lower()


class UserRegister(UserBase):
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def _senha(cls, v: str) -> str:
        return _valida_senha(v)


class UserCreate(UserRegister):
    role: str = "usuario"

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in ROLES:
            raise ValueError(f"role deve ser um de {ROLES}")
        return v


class UserUpdateSelf(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        if v is not None and not EMAIL_RE.match(v):
            raise ValueError("e-mail inválido")
        return v.lower() if v else v


class UserUpdateAdmin(UserUpdateSelf):
    role: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def _role(cls, v):
        if v is not None and v not in ROLES:
            raise ValueError(f"role deve ser um de {ROLES}")
        return v


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
    last_login: Optional[datetime]
    locked_until: Optional[datetime]


class UserList(BaseModel):
    total: int
    items: list[UserOut]


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if not db.scalar(select(func.count()).select_from(User)):
            senha = os.getenv("ADMIN_PASSWORD")
            gerada = senha is None
            senha = senha or secrets.token_urlsafe(12)
            db.add(User(username="admin", email="admin@local", full_name="Administrador",
                        password_hash=hash_password(senha), role="admin"))
            db.commit()
            print("[setup] Usuário 'admin' criado."
                  + (f" Senha gerada: {senha}  (troque assim que logar)" if gerada else ""))
    yield


app = FastAPI(title="API de Gestão de Usuários", version="1.0.0", lifespan=lifespan)


def _checa_duplicidade(db: Session, username: Optional[str], email: Optional[str],
                       ignore_id: Optional[int] = None):
    conds = []
    if username:
        conds.append(User.username == username)
    if email:
        conds.append(User.email == email)
    if not conds:
        return
    q = select(User).where(or_(*conds))
    if ignore_id:
        q = q.where(User.id != ignore_id)
    existente = db.scalar(q)
    if existente:
        campo = "username" if username and existente.username == username else "e-mail"
        raise HTTPException(status.HTTP_409_CONFLICT, f"Já existe um usuário com este {campo}")


@app.get("/health", tags=["infra"])
def health():
    return {"status": "ok"}

@app.post("/auth/register", response_model=UserOut, status_code=201, tags=["auth"])
def register(data: UserRegister, db: Session = Depends(get_db)):
    """Cadastro público. Sempre cria com perfil 'usuario'."""
    _checa_duplicidade(db, data.username, data.email)
    user = User(username=data.username, email=data.email, full_name=data.full_name,
                password_hash=hash_password(data.password), role="usuario")
    db.add(user)
    db.commit()
    return user


@app.post("/auth/login", response_model=Token, tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ident = form.username.lower()
    user = db.scalar(select(User).where(or_(User.username == ident, User.email == ident)))
    invalido = HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuário ou senha incorretos")

    if not user:
        raise invalido
    if user.locked_until and user.locked_until > utcnow():
        raise HTTPException(status.HTTP_423_LOCKED,
                            f"Conta bloqueada até {user.locked_until:%H:%M} (UTC)")
    if not verify_password(form.password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = utcnow() + timedelta(minutes=LOCK_MINUTES)
            user.failed_attempts = 0
        db.commit()
        raise invalido
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Conta desativada")

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = utcnow()
    db.commit()
    return Token(access_token=create_token(user), expires_in=TOKEN_EXPIRE_MINUTES * 60)

@app.get("/users/me", response_model=UserOut, tags=["perfil"])
def me(user: User = Depends(get_current_user)):
    return user


@app.patch("/users/me", response_model=UserOut, tags=["perfil"])
def update_me(data: UserUpdateSelf, user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    _checa_duplicidade(db, None, data.email, ignore_id=user.id)
    for campo, valor in data.model_dump(exclude_unset=True).items():
        if valor is not None:
            setattr(user, campo, valor)
    db.add(user)
    db.commit()
    return user


@app.post("/users/me/password", status_code=204, tags=["perfil"])
def change_password(data: PasswordChange, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Senha atual incorreta")
    user.password_hash = hash_password(data.new_password)
    db.add(user)
    db.commit()


# ------------------------------- Admin -------------------------------------- #
@app.get("/users", response_model=UserList, tags=["admin"])
def list_users(
    q: Optional[str] = Query(None, description="Busca em username, e-mail e nome"),
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    _: User = Depends(require_roles("admin", "tecnico")),
    db: Session = Depends(get_db),
):
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(User.username).like(like),
                              func.lower(User.email).like(like),
                              func.lower(User.full_name).like(like)))
    if role:
        stmt = stmt.where(User.role == role)
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    items = db.scalars(stmt.order_by(User.id).offset(skip).limit(limit)).all()
    return UserList(total=total, items=items)


@app.post("/users", response_model=UserOut, status_code=201, tags=["admin"])
def create_user(data: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    _checa_duplicidade(db, data.username, data.email)
    user = User(username=data.username, email=data.email, full_name=data.full_name,
                password_hash=hash_password(data.password), role=data.role)
    db.add(user)
    db.commit()
    return user


@app.get("/users/{user_id}", response_model=UserOut, tags=["admin"])
def get_user(user_id: int, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.role == "usuario" and current.id != user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sem permissão para esta ação")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado")
    return user


@app.patch("/users/{user_id}", response_model=UserOut, tags=["admin"])
def update_user(user_id: int, data: UserUpdateAdmin, current: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado")
    if user.id == current.id and (data.role not in (None, "admin") or data.is_active is False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Você não pode rebaixar ou desativar a própria conta")
    _checa_duplicidade(db, None, data.email, ignore_id=user.id)
    for campo, valor in data.model_dump(exclude_unset=True).items():
        if valor is not None:
            setattr(user, campo, valor)
    db.add(user)
    db.commit()
    return user


@app.post("/users/{user_id}/reset-password", tags=["admin"])
def reset_password(user_id: int, _: User = Depends(require_admin), db: Session = Depends(get_db)):

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado")
    temp = secrets.token_urlsafe(10)
    user.password_hash = hash_password(temp)
    db.add(user)
    db.commit()
    return {"temporary_password": temp}


@app.post("/users/{user_id}/unlock", response_model=UserOut, tags=["admin"])
def unlock_user(user_id: int, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado")
    user.failed_attempts = 0
    user.locked_until = None
    db.add(user)
    db.commit()
    return user


@app.delete("/users/{user_id}", status_code=204, tags=["admin"])
def delete_user(user_id: int, current: User = Depends(require_admin), db: Session = Depends(get_db)):
    if user_id == current.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Você não pode excluir a própria conta")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuário não encontrado")
    db.delete(user)
    db.commit()
