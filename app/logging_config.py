"""Logging estruturado em JSON (uma linha por evento) + trilha de auditoria."""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

from app.config import Settings

ROOT = "usuarios"
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

audit_logger = logging.getLogger(f"{ROOT}.audit")
access_logger = logging.getLogger(f"{ROOT}.access")
app_logger = logging.getLogger(f"{ROOT}.app")


def audit(event: str, **fields) -> None:
    """Registra um evento de auditoria (quem fez o quê). Nunca passe senhas aqui."""
    audit_logger.info(event, extra={"fields": {"event": event, **fields}})


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = (
            f"{self.formatTime(record)} {record.levelname:<7} {record.name} {record.getMessage()}"
        )
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            base += " " + " ".join(f"{k}={v}" for k, v in fields.items() if k != "event")
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


class _StdoutHandler(logging.StreamHandler):
    """Resolve sys.stdout na hora de emitir (compatível com captura de saída do pytest)."""

    def __init__(self) -> None:
        super().__init__()

    @property
    def stream(self):  # type: ignore[override]
        return sys.stdout

    @stream.setter
    def stream(self, value) -> None:
        pass


def setup_logging(settings: Settings) -> None:
    logger = logging.getLogger(ROOT)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = _StdoutHandler()
    handler.setFormatter(JsonFormatter() if settings.log_json else PlainFormatter())
    logger.addHandler(handler)
    logger.setLevel(settings.log_level.upper())
    logger.propagate = False
