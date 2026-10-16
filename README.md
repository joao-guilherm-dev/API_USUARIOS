# API de Gestão de Usuários

API REST para gestão de usuários com autenticação, controle de permissões e segurança de conta, construída com **FastAPI**.

## ✨ Funcionalidades

- **Autenticação JWT** — login com usuário ou e-mail, cadastro público
- **Controle de permissões (RBAC)** — perfis `admin`, `tecnico` e `usuario`, cada um com um nível de acesso
- **Segurança de senha** — hash com PBKDF2-SHA256 (nunca armazenada em texto puro)
- **Bloqueio de conta** — bloqueio automático após tentativas de login malsucedidas
- **Perfil próprio** — o usuário pode ver e editar seus dados e trocar a própria senha
- **Gestão administrativa** — CRUD completo de usuários, busca, filtros, paginação, reset de senha e desbloqueio de conta
- **Documentação automática** — Swagger UI gerado pelo próprio FastAPI

## 🛠️ Stack

- Python 3.10+
- [FastAPI](https://fastapi.tiangolo.com/)
- [SQLAlchemy 2.0](https://www.sqlalchemy.org/) (ORM)
- [PyJWT](https://pyjwt.readthedocs.io/) (tokens JWT)
- SQLite (banco padrão, trocável via variável de ambiente)

## 🚀 Como rodar

```bash
# Clone o repositório
git clone https://github.com/joao-guilherm-dev/api-gestao-usuarios.git
cd api-gestao-usuarios

# Crie e ative um ambiente virtual
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux/Mac

# Instale as dependências
pip install -r requirements.txt

# Suba a API
uvicorn main:app --reload
```

A API sobe em `http://127.0.0.1:8000`. A documentação interativa fica em `http://127.0.0.1:8000/docs`.

No primeiro start, um usuário `admin` é criado automaticamente e a senha gerada aparece no console — guarde-a para o primeiro login.

## ⚙️ Variáveis de ambiente (opcionais)

| Variável | Descrição | Padrão |
|---|---|---|
| `DATABASE_URL` | String de conexão do banco | `sqlite:///./usuarios.db` |
| `SECRET_KEY` | Chave usada para assinar os tokens JWT | gerada aleatoriamente a cada start |
| `ADMIN_PASSWORD` | Senha fixa para o admin inicial | gerada aleatoriamente |
| `TOKEN_EXPIRE_MINUTES` | Validade do token JWT (minutos) | `60` |
| `MAX_FAILED_ATTEMPTS` | Tentativas de login antes de bloquear | `5` |
| `LOCK_MINUTES` | Duração do bloqueio de conta (minutos) | `15` |

Em produção, defina sempre `SECRET_KEY` fixo — caso contrário, todos os tokens são invalidados a cada reinício da API.

## 📋 Principais endpoints

| Método | Rota | Descrição | Acesso |
|---|---|---|---|
| POST | `/auth/register` | Cadastro público | Livre |
| POST | `/auth/login` | Login (retorna token JWT) | Livre |
| GET | `/users/me` | Ver o próprio perfil | Autenticado |
| PATCH | `/users/me` | Editar o próprio perfil | Autenticado |
| POST | `/users/me/password` | Trocar a própria senha | Autenticado |
| GET | `/users` | Listar usuários (busca, filtros, paginação) | Admin/Técnico |
| POST | `/users` | Criar usuário | Admin |
| GET | `/users/{id}` | Ver um usuário | Admin/Técnico/Dono |
| PATCH | `/users/{id}` | Editar um usuário | Admin |
| DELETE | `/users/{id}` | Excluir um usuário | Admin |
| POST | `/users/{id}/reset-password` | Gerar senha temporária | Admin |
| POST | `/users/{id}/unlock` | Desbloquear conta | Admin |

## ✅ Testes

O projeto inclui um script de testes automatizados cobrindo os principais fluxos (login, permissões, bloqueio de conta, etc.):

```bash
python test_api.py
```

## 📌 Próximos passos

Este serviço foi pensado para ser o módulo de autenticação de uma arquitetura maior, com várias APIs conectadas a um banco de dados único.

## 📄 Licença

Este projeto é livre para uso educacional e como referência de portfólio.
