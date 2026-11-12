import json
import logging

from fastapi.testclient import TestClient

from app.logging_config import JsonFormatter
from tests.conftest import login


def test_404_uses_standard_error_shape(client):
    r = client.get("/nao-existe")
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["code"] == "not_found"
    assert body["detail"] == "Not Found"
    assert body["error"]["request_id"] == r.headers["x-request-id"]


def test_request_id_is_propagated_when_valid_and_replaced_when_not(client):
    r = client.get("/health", headers={"X-Request-ID": "meu-id-12345"})
    assert r.headers["x-request-id"] == "meu-id-12345"
    r = client.get("/health", headers={"X-Request-ID": "invalido com espaco"})
    assert r.headers["x-request-id"] != "invalido com espaco"
    assert len(r.headers["x-request-id"]) == 32


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_unhandled_exception_returns_json_500_without_leaking_details(app):
    @app.get("/boom")
    def boom():
        raise RuntimeError("segredo interno")

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/boom")
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "server_error"
    assert "segredo" not in r.text
    assert r.headers["x-request-id"]


def test_audit_trail_records_events_and_never_passwords(client, audit_records, usuario):
    for _ in range(3):
        login(client, "joao", "SenhaErrada99")
    login(client, "admin", "Admin1234")
    events = audit_records()
    names = [e["event"] for e in events]
    assert "user_created" in names and "login_success" in names
    assert names.count("login_failed") == 3 and "account_locked" in names
    dump = json.dumps(events, default=str)
    assert "SenhaErrada99" not in dump and "Admin1234" not in dump


def test_json_formatter_outputs_valid_json_with_fields():
    record = logging.LogRecord("usuarios.test", logging.INFO, __file__, 1, "evento", None, None)
    record.fields = {"event": "evento", "user_id": 7}
    data = json.loads(JsonFormatter().format(record))
    assert data["message"] == "evento" and data["user_id"] == 7 and data["level"] == "INFO"
    assert data["ts"].endswith("+00:00")


def test_production_requires_strong_secret():
    import pytest

    from app.config import Settings

    with pytest.raises(ValueError):
        Settings(_env_file=None, environment="production", secret_key="")
    with pytest.raises(ValueError):
        Settings(_env_file=None, environment="production", secret_key="curta")
    ok = Settings(_env_file=None, environment="production", secret_key="x" * 40)
    assert ok.is_production
