"""Configuração da aplicação, lida de variáveis de ambiente (ou de um arquivo .env)."""

import secrets
from functools import lru_cache

from pydantic import PrivateAttr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./usuarios.db"
    secret_key: str = ""
    token_expire_minutes: int = 60
    max_failed_attempts: int = 5
    lock_minutes: int = 15
    pbkdf2_iterations: int = 200_000
    admin_email: str = "admin@example.com"
    admin_password: str | None = None
    log_level: str = "INFO"
    log_json: bool = True

    _secret_generated: bool = PrivateAttr(default=False)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def secret_generated(self) -> bool:
        return self._secret_generated

    @model_validator(mode="after")
    def _check_secret(self) -> "Settings":
        if not self.secret_key:
            if self.is_production:
                raise ValueError("SECRET_KEY é obrigatória quando ENVIRONMENT=production")
            self.secret_key = secrets.token_hex(32)
            self._secret_generated = True
        elif self.is_production and len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY deve ter pelo menos 32 caracteres em produção")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
