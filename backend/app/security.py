"""Proteções da API: token administrativo, limite de requisições e cabeçalhos."""
from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from app import config


def require_admin(x_admin_token: str | None = Header(None)):
    """Protege rotas administrativas. Sem ADMIN_TOKEN configurado, elas ficam desligadas."""
    if not config.ADMIN_TOKEN:
        raise HTTPException(status_code=404, detail="Not Found")
    if not x_admin_token or not hmac.compare_digest(x_admin_token, config.ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Token administrativo inválido.")


def client_ip(request: Request) -> str:
    # Atrás do proxy do Render, request.client é o proxy; o IP real vem no X-Forwarded-For.
    # (Funciona com ou sem --proxy-headers no comando de start.)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Janela deslizante em memória, por chave (IP). Suficiente para 1 instância."""

    def __init__(self, max_calls: int, period_seconds: float = 60.0):
        self.max_calls = max_calls
        self.period = period_seconds
        self._calls: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            calls = self._calls[key]
            while calls and now - calls[0] > self.period:
                calls.popleft()
            if len(calls) >= self.max_calls:
                return False
            calls.append(now)
            if len(self._calls) > 10_000:  # evita crescer sem limite
                for k in [k for k, v in self._calls.items() if not v]:
                    del self._calls[k]
            return True

    def check(self, request: Request):
        if not self.hit(client_ip(request)):
            raise HTTPException(
                status_code=429,
                detail="Muitas requisições. Aguarde um minuto e tente novamente.",
                headers={"Retry-After": str(int(self.period))},
            )


ai_limiter = RateLimiter(config.RATE_LIMIT_AI_PER_MIN)
search_limiter = RateLimiter(config.RATE_LIMIT_SEARCH_PER_MIN)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        return response
