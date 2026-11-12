from tests.conftest import login


def _item(name, **extra):
    return {"username": name, "email": f"{name}@example.com", **extra}


def test_export_shape_and_no_secrets(client, admin, usuario):
    r = client.get("/users/export", headers=admin)
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    body = r.json()
    assert body["count"] == 2 and len(body["users"]) == 2
    assert {"username", "email", "full_name", "role", "is_active", "created_at"} == set(
        body["users"][0]
    )
    assert "password" not in r.text and "hash" not in r.text


def test_export_and_import_require_admin(client, tecnico, usuario):
    for headers in (tecnico, usuario["headers"]):
        assert client.get("/users/export", headers=headers).status_code == 403
        r = client.post("/users/import", json={"users": [_item("x1x")]}, headers=headers)
        assert r.status_code == 403


def test_import_creates_users_and_generates_temp_passwords(client, admin):
    payload = {"users": [_item("ana", role="tecnico"), _item("bia", password="Minha1234")]}
    r = client.post("/users/import", json=payload, headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2 and len(body["created"]) == 2 and not body["skipped"]
    ana, bia = body["created"]
    assert ana["temporary_password"] and bia["temporary_password"] is None
    assert login(client, "ana", ana["temporary_password"]).status_code == 200
    assert login(client, "bia", "Minha1234").status_code == 200
    assert client.get("/users?role=tecnico", headers=admin).json()["total"] == 1


def test_import_reports_invalid_and_duplicate_items_without_failing_the_rest(
    client, admin, usuario
):
    payload = {
        "users": [
            _item("novo1"),
            {"username": "ab", "email": "ruim"},  # inválido
            _item("joao"),  # já existe no banco
            _item("novo1"),  # duplicado no arquivo
            _item("novo2", password="semnumero"),  # senha fraca
            _item("novo3"),
        ]
    }
    body = client.post("/users/import", json=payload, headers=admin).json()
    assert [c["username"] for c in body["created"]] == ["novo1", "novo3"]
    reasons = {s["index"]: s["reason"] for s in body["skipped"]}
    assert set(reasons) == {1, 2, 3, 4}
    assert "já existe" in reasons[2] and "duplicado" in reasons[3]


def test_import_dry_run_writes_nothing(client, admin):
    r = client.post(
        "/users/import", json={"users": [_item("fantasma")], "dry_run": True}, headers=admin
    )
    body = r.json()
    assert body["dry_run"] is True and len(body["created"]) == 1
    assert body["created"][0]["id"] is None and body["created"][0]["temporary_password"] is None
    assert client.get("/users?q=fantasma", headers=admin).json()["total"] == 0


def test_import_size_limits(client, admin):
    too_many = {"users": [_item(f"user{i:03d}") for i in range(101)]}
    assert client.post("/users/import", json=too_many, headers=admin).status_code == 422
    assert client.post("/users/import", json={"users": []}, headers=admin).status_code == 422


def test_export_then_import_roundtrip_skips_existing(client, admin, usuario):
    exported = client.get("/users/export", headers=admin).json()
    # admin@example.com e joao já existem -> tudo é pulado, nada quebra
    body = client.post("/users/import", json={"users": exported["users"]}, headers=admin).json()
    assert len(body["created"]) == 0 and len(body["skipped"]) == 2
