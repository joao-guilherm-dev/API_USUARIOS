import os
os.environ["DATABASE_URL"] = "sqlite:///./test_usuarios.db"
os.environ["ADMIN_PASSWORD"] = "Admin1234"
os.environ["SECRET_KEY"] = "teste"
os.environ["MAX_FAILED_ATTEMPTS"] = "3"
from fastapi.testclient import TestClient
from main import app

def login(c, u, p):
    return c.post("/auth/login", data={"username": u, "password": p})

def hdr(tok): return {"Authorization": f"Bearer {tok}"}

with TestClient(app) as c:
    assert c.get("/health").json() == {"status": "ok"}
    r = login(c, "admin", "Admin1234"); assert r.status_code == 200, r.text
    adm = r.json()["access_token"]

    r = c.post("/auth/register", json={"username": "Joao", "email": "joao@x.com", "password": "senha1234", "full_name": "João"})
    assert r.status_code == 201 and r.json()["role"] == "usuario", r.text
    assert c.post("/auth/register", json={"username": "joao", "email": "outro@x.com", "password": "senha1234"}).status_code == 409
    assert c.post("/auth/register", json={"username": "ab", "email": "x", "password": "123"}).status_code == 422

    u = login(c, "joao@x.com", "senha1234").json()["access_token"]
    assert c.get("/users/me", headers=hdr(u)).json()["username"] == "joao"
    assert c.get("/users", headers=hdr(u)).status_code == 403
    assert c.get("/users", headers=hdr(adm)).json()["total"] == 2
    assert c.get("/users?q=joa", headers=hdr(adm)).json()["total"] == 1
    assert c.get("/users/1", headers=hdr(u)).status_code == 403

    assert c.patch("/users/me", json={"full_name": "João G."}, headers=hdr(u)).json()["full_name"] == "João G."
    assert c.post("/users/me/password", json={"current_password": "errada", "new_password": "nova12345"}, headers=hdr(u)).status_code == 400
    assert c.post("/users/me/password", json={"current_password": "senha1234", "new_password": "nova12345"}, headers=hdr(u)).status_code == 204
    assert login(c, "joao", "nova12345").status_code == 200

    r = c.post("/users", json={"username": "tec1", "email": "t@x.com", "password": "tecnico123", "role": "tecnico"}, headers=hdr(adm))
    assert r.status_code == 201
    tid = r.json()["id"]
    tt = login(c, "tec1", "tecnico123").json()["access_token"]
    assert c.get("/users", headers=hdr(tt)).status_code == 200
    assert c.post("/users", json={"username": "z", "email": "z@z.com", "password": "abc12345"}, headers=hdr(tt)).status_code == 403

    for _ in range(3): assert login(c, "tec1", "x").status_code == 401
    assert login(c, "tec1", "tecnico123").status_code == 423
    assert c.post(f"/users/{tid}/unlock", headers=hdr(adm)).status_code == 200
    assert login(c, "tec1", "tecnico123").status_code == 200

    assert c.patch("/users/1", json={"role": "usuario"}, headers=hdr(adm)).status_code == 400
    assert c.patch(f"/users/{tid}", json={"is_active": False}, headers=hdr(adm)).json()["is_active"] is False
    assert login(c, "tec1", "tecnico123").status_code == 403
    assert c.get("/users/me", headers=hdr(tt)).status_code == 401
    assert "temporary_password" in c.post(f"/users/{tid}/reset-password", headers=hdr(adm)).json()
    assert c.delete("/users/1", headers=hdr(adm)).status_code == 400
    assert c.delete(f"/users/{tid}", headers=hdr(adm)).status_code == 204
    assert c.get(f"/users/{tid}", headers=hdr(adm)).status_code == 404
    print("TUDO OK")
