from tests.conftest import bearer, login, token_for


def test_list_permissions(client, admin, tecnico, usuario):
    assert client.get("/users", headers=usuario["headers"]).status_code == 403
    assert client.get("/users", headers=tecnico).status_code == 200
    assert client.get("/users", headers=admin).json()["total"] == 3


def test_list_search_filters_and_pagination(client, admin, create_user):
    for name in ("ana", "bruno", "carla"):
        create_user(name, role="tecnico" if name == "bruno" else "usuario")
    assert client.get("/users?q=BRU", headers=admin).json()["total"] == 1
    assert client.get("/users?role=tecnico", headers=admin).json()["total"] == 1
    assert client.get("/users?is_active=false", headers=admin).json()["total"] == 0
    page = client.get("/users?limit=2&skip=1", headers=admin).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    assert client.get("/users?role=chefe", headers=admin).status_code == 422
    assert client.get("/users?limit=1000", headers=admin).status_code == 422


def test_create_requires_admin(client, tecnico):
    payload = {"username": "zed", "email": "z@example.com", "password": "abc12345"}
    assert client.post("/users", json=payload, headers=tecnico).status_code == 403


def test_create_with_invalid_role_is_422(client, admin):
    payload = {"username": "zed", "email": "z@example.com", "password": "abc12345", "role": "deus"}
    assert client.post("/users", json=payload, headers=admin).status_code == 422


def test_get_user_permissions(client, admin, tecnico, usuario, create_user):
    other = create_user("maria")
    assert client.get(f"/users/{usuario['id']}", headers=usuario["headers"]).status_code == 200
    assert client.get(f"/users/{other['id']}", headers=usuario["headers"]).status_code == 403
    assert client.get(f"/users/{other['id']}", headers=tecnico).status_code == 200
    assert client.get("/users/9999", headers=admin).status_code == 404


def test_me_route_is_not_captured_by_dynamic_route(client, usuario):
    assert client.get("/users/me", headers=usuario["headers"]).status_code == 200


def test_admin_cannot_demote_deactivate_or_delete_self(client, admin):
    assert client.patch("/users/1", json={"role": "usuario"}, headers=admin).status_code == 400
    assert client.patch("/users/1", json={"is_active": False}, headers=admin).status_code == 400
    assert client.delete("/users/1", headers=admin).status_code == 400


def test_patch_and_delete_user(client, admin, create_user):
    user = create_user("maria")
    r = client.patch(f"/users/{user['id']}", json={"role": "tecnico"}, headers=admin)
    assert r.json()["role"] == "tecnico"
    assert client.delete(f"/users/{user['id']}", headers=admin).status_code == 204
    assert client.get(f"/users/{user['id']}", headers=admin).status_code == 404
    assert client.delete(f"/users/{user['id']}", headers=admin).status_code == 404


def test_reset_password_gives_working_temp_password_and_kills_old_tokens(client, admin, usuario):
    r = client.post(f"/users/{usuario['id']}/reset-password", headers=admin)
    temp = r.json()["temporary_password"]
    assert client.get("/users/me", headers=usuario["headers"]).status_code == 401
    assert login(client, "joao", "Senha1234").status_code == 401
    assert bearer(token_for(client, "joao", temp))
