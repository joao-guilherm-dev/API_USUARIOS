import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Any

import jwt

from app.config import Settings
from app.models import User, utcnow

ALGORITHM = "HS256"
DEFAULT_ITERATIONS = 200_000


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
        new = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(new.hex(), digest)
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str, iterations: int) -> bool:
    """True se o hash guardado usa menos iterações que a configuração atual."""
    try:
        return int(stored.split("$")[1]) < iterations
    except (IndexError, ValueError):
        return True


# Hash "fantasma": usado quando o usuário não existe, para que o login leve o mesmo
# tempo com usuário válido ou inválido (evita enumeração de usuários por timing).
DUMMY_HASH = hash_password("senha-fantasma")


def create_token(user: User, settings: Settings) -> str:
    now = utcnow()
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "ver": user.token_version,
        "iat": now,
        "exp": now + timedelta(minutes=settings.token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str, settings: Settings) -> dict[str, Any]:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
