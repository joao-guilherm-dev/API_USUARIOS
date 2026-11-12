# API de Gestão de Usuários

[![CI](https://github.com/joao-guilherm-dev/API_USUARIOS/actions/workflows/ci.yml/badge.svg)](https://github.com/joao-guilherm-dev/API_USUARIOS/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-009688)

API REST em **FastAPI** para gerenciar usuários: autenticação JWT, perfis de acesso (RBAC),
bloqueio de conta por tentativas, trilha de auditoria em JSON e importação/exportação de usuários.

## Funcionalidades

- **Autenticação JWT** (login por username ou e-mail) com tokens que **expiram e são invalidados**
  ao trocar/resetar a senha
- **Perfis**: `admin`, `tecnico`, `usuario` (RBAC por dependência)
- **Bloqueio de conta** após N tentativas erradas (`423` + `Retry-After`) e desbloqueio pelo admin
- **Hash PBKDF2-SHA256** com salt, com *rehash* automático se o custo aumentar
- Login resistente a **enumeração de usuários** (mesma resposta e mesmo tempo)
- **Logs em JSON** (access log + auditoria), com `X-Request-ID` ligando tudo
- **Erros padronizados em JSON** (mantendo o campo `detail` do FastAPI)
- **Export/Import de usuários em JSON** (com validação por item e `dry_run`)
- Health checks `/health` e `/ready`, Docker, Postgres opcional, CI no GitHub Actions

## Rodando local

```bash
python -m venv venv && venv\Scripts\activate      # Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                              # Windows: copy .env.example .env
uvicorn app.main:app --reload
```

Docs interativas em http://localhost:8000/docs. No primeiro start é criado o usuário `admin`
(senha em `ADMIN_PASSWORD`, ou gerada e impressa no console).

## Docker

```bash
# SQLite, rápido para testar
docker build -t api-usuarios .
docker run -p 8000:8000 -e SECRET_KEY=$(openssl rand -hex 32) -v usuarios-data:/data api-usuarios

# API + PostgreSQL (defina SECRET_KEY e POSTGRES_PASSWORD no .env)
docker compose up --build
```

## Configuração (variáveis de ambiente)

| Variável | Padrão | Descrição |
|---|---|---|
| `ENVIRONMENT` | `development` | Em `production`, `SECRET_KEY` é obrigatória (≥ 32 caracteres) |
| `SECRET_KEY` | aleatória | Chave de assinatura do JWT |
| `DATABASE_URL` | `sqlite:///./usuarios.db` | Qualquer URL do SQLAlchemy (ex.: `postgresql+psycopg://...`) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@example.com` / aleatória | Admin criado no primeiro start |
| `TOKEN_EXPIRE_MINUTES` | `60` | Validade do token |
| `MAX_FAILED_ATTEMPTS` / `LOCK_MINUTES` | `5` / `15` | Política de bloqueio |
| `LOG_LEVEL` / `LOG_JSON` | `INFO` / `true` | `LOG_JSON=false` dá logs em texto legível |

## Endpoints

| Método | Rota | Acesso |
|---|---|---|
| POST | `/auth/register` | público (sempre cria `usuario`) |
| POST | `/auth/login` | público (form OAuth2) |
| GET / PATCH | `/users/me` | autenticado |
| POST | `/users/me/password` | autenticado (invalida tokens antigos) |
| GET | `/users` | admin, tecnico (busca `q`, filtros `role`/`is_active`, paginação) |
| GET | `/users/{id}` | admin, tecnico, ou o próprio usuário |
| POST / PATCH / DELETE | `/users`, `/users/{id}` | admin |
| POST | `/users/{id}/reset-password` · `/unlock` | admin |
| GET | `/users/export` | admin |
| POST | `/users/import` | admin |
| GET | `/health` · `/ready` | público |

## JSON

**Erros** (todos têm o mesmo formato; `detail` continua igual ao padrão do FastAPI):

```json
{
  "detail": "Usuário ou senha incorretos",
  "error": { "code": "unauthorized", "message": "Usuário ou senha incorretos", "request_id": "c0594e26..." }
}
```

Erros de validação (`422`) trazem `error.details` com `field` e `message` por campo.

**Importação** (`POST /users/import`, até 100 usuários; itens inválidos ou duplicados são
reportados sem derrubar o resto; `dry_run: true` só simula):

```json
{
  "dry_run": false,
  "users": [
    { "username": "ana", "email": "ana@empresa.com", "role": "tecnico" },
    { "username": "bia", "email": "bia@empresa.com", "password": "Minha1234" }
  ]
}
```

Sem `password`, a API gera uma senha temporária, devolvida **uma única vez** na resposta.
O arquivo de `/users/export` (sem senhas) pode ser reimportado em outra instância.

**Logs** — uma linha JSON por evento. Exemplo de auditoria:

```json
{"ts":"2026-11-12T16:13:15.588+00:00","level":"INFO","logger":"usuarios.audit","message":"login_failed","request_id":"c0594e26...","event":"login_failed","reason":"bad_password","username":"admin","attempts":1,"ip":"127.0.0.1"}
```

Eventos: `login_success`, `login_failed`, `login_blocked`, `account_locked`, `user_registered`,
`user_created`, `user_updated`, `user_deleted`, `password_changed`, `password_reset`,
`user_unlocked`, `users_exported`, `users_imported`. Senhas nunca são registradas.

## Desenvolvimento

```bash
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest --cov
```

## CI (GitHub Actions)

A cada push/PR: **lint** (ruff), **testes** em Python 3.10–3.13 com cobertura mínima de 90%,
**pip-audit** nas dependências e **build Docker + smoke test** (sobe o container e chama
`/health`, `/ready` e `/auth/login`). O Dependabot atualiza pip, Actions e Docker semanalmente.

## Estrutura

```
app/
├── factory.py        # create_app(): monta tudo (e permite testar com config isolada)
├── config.py         # Settings via variáveis de ambiente
├── security.py       # hash de senha e JWT
├── deps.py           # sessão de banco, usuário atual, RBAC
├── errors.py         # erros padronizados em JSON
├── logging_config.py # logs JSON + auditoria
├── middleware.py     # X-Request-ID, access log, headers de segurança
├── routers/          # auth, me (perfil), users (admin)
└── schemas.py · models.py · services.py · database.py
tests/                # pytest (banco SQLite temporário por teste)
```

## Próximos passos

Migrações com Alembic, rate limit por IP no login e refresh tokens.

## Licença

Projeto de estudo/portfólio, livre para uso educacional.
