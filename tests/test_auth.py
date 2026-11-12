from tests.conftest import ADMIN_PASSWORD, bearer, login, token_for


def test_health_and_ready(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/ready").json() == {"status": "ready"}


def test_register_creates_regular_user_and_ignores_role(client):
    r = client.post(
        "/auth/register",
        json={
            "username": "Joao",
            "email": "Joao@Example.com",
            "password": "senha1234",
            "role": "admin",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["role"] == "usuario"
    assert body["username"] == "joao" and body["email"] == "joao@example.com"
    assert "password" not in body and "password_hash" not in body


def test_register_duplicate_returns_409(client):
    payload = {"username": "joao", "email": "joao@example.com", "password": "senha1234"}
    assert client.post("/auth/register", json=payload).status_code == 201
    dup_user = {**payload, "email": "outro@example.com"}
    assert client.post("/auth/register", json=dup_user).status_code == 409
    dup_mail = {**payload, "username": "outro"}
    assert client.post("/auth/register", json=dup_mail).status_code == 409


def test_register_validation_error_has_standard_json_shape(client):
    r = client.post("/auth/register", json={"username": "ab", "email": "x", "password": "123"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["code"] == "validation_error"
    fields = {d["field"] for d in body["error"]["details"]}
    assert {"body.username", "body.email", "body.password"} <= fields
    assert isinstance(body["detail"], list) and body["detail"][0]["loc"]


def test_login_by_username_and_by_email(client, usuario):
    assert login(client, "joao", "Senha1234").status_code == 200
    assert login(client, "JOAO@example.com", "Senha1234").status_code == 200


def test_login_unknown_user_and_wrong_password_look_the_same(client, usuario):
    a = login(client, "naoexiste", "Senha1234")
    b = login(client, "joao", "errada123")
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_account_locks_after_max_attempts_and_admin_can_unlock(client, admin, usuario):
    for _ in range(3):
        assert login(client, "joao", "x").status_code == 401
    r = login(client, "joao", "Senha1234")
    assert r.status_code == 423
    assert int(r.headers["retry-after"]) > 0
    assert client.post(f"/users/{usuario['id']}/unlock", headers=admin).status_code == 200
    assert login(client, "joao", "Senha1234").status_code == 200


def test_inactive_user_cannot_login_and_token_stops_working(client, admin, usuario):
    r = client.patch(f"/users/{usuario['id']}", json={"is_active": False}, headers=admin)
    assert r.json()["is_active"] is False
    assert login(client, "joao", "Senha1234").status_code == 403
    assert client.get("/users/me", headers=usuario["headers"]).status_code == 401


def test_missing_and_invalid_tokens_are_401(client):
    assert client.get("/users/me").status_code == 401
    r = client.get("/users/me", headers=bearer("lixo"))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_password_hash_is_upgraded_when_iterations_increase(app, client, usuario):
    from sqlalchemy import select

    from app.models import User

    app.state.settings.pbkdf2_iterations = 2_000
    assert login(client, "joao", "Senha1234").status_code == 200
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "joao"))
        assert user.password_hash.split("$")[1] == "2000"


def test_admin_seed_uses_configured_password(client):
    assert login(client, "admin", ADMIN_PASSWORD).status_code == 200
    assert token_for(client, "admin@example.com", ADMIN_PASSWORD)
