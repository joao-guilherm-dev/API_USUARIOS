"""Respostas de erro padronizadas em JSON.

Formato:
    {
      "detail": ...,                       # compatível com o padrão do FastAPI
      "error": {"code": "...", "message": "...", "request_id": "...", "details": [...]}
    }
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.logging_config import app_logger

_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    423: "locked",
    429: "too_many_requests",
}


def clean_error_message(msg: str) -> str:
    return msg.removeprefix("Value error, ")


def _code(status_code: int) -> str:
    return _CODES.get(status_code, "server_error" if status_code >= 500 else "http_error")


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def _body(request: Request, status_code: int, message: str, detail, details=None) -> dict:
    error: dict = {
        "code": _code(status_code),
        "message": message,
        "request_id": _request_id(request),
    }
    if details:
        error["details"] = details
    return {"detail": detail, "error": error}


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Erro na requisição"
    return JSONResponse(
        _body(request, exc.status_code, message, exc.detail),
        status_code=exc.status_code,
        headers=getattr(exc, "headers", None),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    detail = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    details = [
        {"field": ".".join(str(p) for p in e["loc"]), "message": clean_error_message(e["msg"])}
        for e in exc.errors()
    ]
    return JSONResponse(_body(request, 422, "Dados inválidos", detail, details), status_code=422)


async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:
    app_logger.warning("integrity_error", extra={"fields": {"event": "integrity_error"}})
    message = "Conflito: registro duplicado ou inconsistente"
    return JSONResponse(_body(request, 409, message, message), status_code=409)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = _request_id(request)
    app_logger.error(
        "unhandled_exception",
        exc_info=(type(exc), exc, exc.__traceback__),
        extra={
            "fields": {"event": "unhandled_exception", "request_id": rid, "path": request.url.path}
        },
    )
    message = "Erro interno do servidor"
    headers = {"X-Request-ID": rid} if rid else None
    return JSONResponse(_body(request, 500, message, message), status_code=500, headers=headers)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(IntegrityError, integrity_error_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
