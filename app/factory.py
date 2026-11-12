import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.orm import sessionmaker

from app import __version__
from app.config import Settings, get_settings
from app.database import Base, make_engine
from app.errors import register_error_handlers
from app.logging_config import app_logger, setup_logging
from app.middleware import RequestContextMiddleware
from app.models import User
from app.routers import auth, me, users
from app.security import hash_password


def seed_admin(session_factory, settings: Settings) -> None:
    with session_factory() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return
        senha = settings.admin_password
        gerada = senha is None
        senha = senha or secrets.token_urlsafe(12)
        db.add(
            User(
                username="admin",
                email=settings.admin_email,
                full_name="Administrador",
                password_hash=hash_password(senha, settings.pbkdf2_iterations),
                role="admin",
            )
        )
        db.commit()
    app_logger.info("admin_created", extra={"fields": {"event": "admin_created"}})
    if gerada:
        # print (e não log) de propósito: a senha nunca entra no pipeline de logs.
        print(f"[setup] Usuário 'admin' criado. Senha gerada: {senha}  (troque assim que logar)")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings)
    if settings.secret_generated:
        app_logger.warning(
            "SECRET_KEY não definida: gerada aleatoriamente "
            "(os tokens deixam de valer quando a API reiniciar).",
            extra={"fields": {"event": "secret_key_generated"}},
        )

    engine = make_engine(settings.database_url)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        Base.metadata.create_all(engine)
        seed_admin(session_factory, settings)
        yield
        engine.dispose()

    app = FastAPI(
        title="API de Gestão de Usuários",
        version=__version__,
        description="Autenticação JWT, RBAC, bloqueio de conta, auditoria e import/export em JSON.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory

    register_error_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(auth.router)
    app.include_router(me.router)  # antes de users: /users/me não pode cair em /users/{id}
    app.include_router(users.router)

    @app.get("/health", tags=["infra"])
    def health():
        return {"status": "ok"}

    @app.get("/ready", tags=["infra"])
    def ready():
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ready"}

    return app
