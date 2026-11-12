import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.factory import create_app

ADMIN_PASSWORD = "Admin1234"


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        secret_key="test-secret-key-test-secret-key-0000",
        admin_password=ADMIN_PASSWORD,
        max_failed_attempts=3,
        lock_minutes=15,
        pbkdf2_iterations=1_000,  # rápido nos testes
    )


@pytest.fixture
def app(settings):
    application = create_app(settings)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def audit_records():
    """Lista (viva) dos `fields` de cada evento de auditoria emitido durante o teste."""
    handler = ListHandler()
    logger = logging.getLogger("usuarios.audit")
    logger.addHandler(handler)
    yield lambda: [r.fields for r in handler.records]
    logger.removeHandler(handler)


def login(client, username, password):
    return client.post("/auth/login", data={"username": username, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def token_for(client, username, password):
    r = login(client, username, password)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def admin_token(client):
    return token_for(client, "admin", ADMIN_PASSWORD)


@pytest.fixture
def admin(admin_token):
    return bearer(admin_token)


@pytest.fixture
def create_user(client, admin):
    def _create(username, role="usuario", password="Senha1234", **extra):
        payload = {
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "role": role,
            **extra,
        }
        r = client.post("/users", json=payload, headers=admin)
        assert r.status_code == 201, r.text
        return r.json()

    return _create


@pytest.fixture
def tecnico(client, create_user):
    create_user("tec1", role="tecnico", password="Tecnico123")
    return bearer(token_for(client, "tec1", "Tecnico123"))


@pytest.fixture
def usuario(client, create_user):
    user = create_user("joao", password="Senha1234")
    return {"id": user["id"], "headers": bearer(token_for(client, "joao", "Senha1234"))}
