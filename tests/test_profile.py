from tests.conftest import bearer, login, token_for


def test_me_returns_own_profile(client, usuario):
    r = client.get("/users/me", headers=usuario["headers"])
    assert r.status_code == 200 and r.json()["username"] == "joao"


def test_update_profile(client, usuario):
    r = client.patch("/users/me", json={"full_name": "João G."}, headers=usuario["headers"])
    assert r.json()["full_name"] == "João G."


def test_update_email_conflict(client, usuario, create_user):
    create_user("maria")
    r = client.patch("/users/me", json={"email": "maria@example.com"}, headers=usuario["headers"])
    assert r.status_code == 409


def test_cannot_change_own_role_via_profile(client, usuario):
    client.patch("/users/me", json={"role": "admin"}, headers=usuario["headers"])
    assert client.get("/users/me", headers=usuario["headers"]).json()["role"] == "usuario"


def test_change_password_flow_invalidates_old_tokens(client, usuario):
    h = usuario["headers"]
    wrong = {"current_password": "errada", "new_password": "nova12345"}
    assert client.post("/users/me/password", json=wrong, headers=h).status_code == 400
    weak = {"current_password": "Senha1234", "new_password": "semnumero"}
    assert client.post("/users/me/password", json=weak, headers=h).status_code == 422
    ok = {"current_password": "Senha1234", "new_password": "nova12345"}
    assert client.post("/users/me/password", json=ok, headers=h).status_code == 204
    assert client.get("/users/me", headers=h).status_code == 401  # token antigo morreu
    assert login(client, "joao", "Senha1234").status_code == 401
    assert bearer(token_for(client, "joao", "nova12345"))
