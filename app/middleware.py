import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.logging_config import access_logger, request_id_var

_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_QUIET_PATHS = {"/health", "/ready"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Gera/propaga X-Request-ID, escreve o access log em JSON e põe headers de segurança."""

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        request.state.request_id = request_id
        token = request_id_var.set(request_id)
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            for name, value in SECURITY_HEADERS.items():
                response.headers.setdefault(name, value)
            return response
        finally:
            if request.url.path not in _QUIET_PATHS:
                access_logger.info(
                    "http_request",
                    extra={
                        "fields": {
                            "event": "http_request",
                            "method": request.method,
                            "path": request.url.path,
                            "status": status_code,
                            "duration_ms": round((time.perf_counter() - start) * 1000, 1),
                            "client": request.client.host if request.client else None,
                        }
                    },
                )
            request_id_var.reset(token)
