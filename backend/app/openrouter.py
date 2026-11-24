"""Provedor reserva: OpenRouter (https://openrouter.ai), SOMENTE com modelos gratuitos.

Regras para nunca gerar custo:
- Só são enviados modelos com preço zero no catálogo público do OpenRouter
  (IDs terminados em ":free" ou o roteador "openrouter/free"). Qualquer outro é descartado.
- Sem busca na web (o plugin "web" é cobrado mesmo com modelos gratuitos).
- Só modelos gratuitos na lista: assim o OpenRouter nunca troca para um modelo pago.

Limite do plano gratuito do OpenRouter: 20 pedidos/minuto e 50 pedidos/dia por conta.
"""
from __future__ import annotations

import logging
import threading
import time

import httpx

from app import config

logger = logging.getLogger(__name__)

API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODELS_URL = "https://openrouter.ai/api/v1/models"
FREE_ROUTER = "openrouter/free"
SYSTEM_PROMPT = (
    "Você é um analista sênior de inteligência de ameaças. Responda com precisão técnica, "
    "seguindo exatamente o formato pedido. Se não tiver certeza de um número de KB ou versão, "
    "diga que não foi confirmado em vez de inventar."
)

_catalog_lock = threading.Lock()
_catalog: dict = {"free": None, "at": 0.0}
_CATALOG_TTL = 3600


class OpenRouterError(Exception):
    def __init__(self, status: int, message: str, error_type: str = "", retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.error_type = error_type
        self.retry_after = retry_after


def is_free_id(model_id: str) -> bool:
    return model_id.endswith(":free") or model_id == FREE_ROUTER


def _free_catalog() -> set[str] | None:
    """IDs com preço zero (entrada e saída) no catálogo público. None se não deu para consultar."""
    with _catalog_lock:
        if _catalog["free"] is not None and time.monotonic() - _catalog["at"] < _CATALOG_TTL:
            return _catalog["free"]
        try:
            with httpx.Client(timeout=15.0) as client:
                data = client.get(MODELS_URL).json().get("data", [])
            free = {
                m["id"] for m in data
                if str((m.get("pricing") or {}).get("prompt")) == "0"
                and str((m.get("pricing") or {}).get("completion")) == "0"
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Não foi possível consultar o catálogo do OpenRouter: %s", type(exc).__name__)
            return None
        _catalog.update(free=free, at=time.monotonic())
        return free


def free_models() -> list[str]:
    """Modelos gratuitos em ordem de preferência, sempre terminando no roteador gratuito."""
    preferred = [m for m in config.OPENROUTER_MODELS if is_free_id(m) and m != FREE_ROUTER]
    catalog = _free_catalog()
    if catalog is not None:
        preferred = [m for m in preferred if m in catalog]
    return preferred[:2] + [FREE_ROUTER]


def _retry_after(resp: httpx.Response) -> int | None:
    try:
        return int(float(resp.headers.get("retry-after", "")))
    except ValueError:
        return None


def generate(api_key: str, prompt: str) -> tuple[str, str]:
    """Devolve (texto, modelo_que_respondeu). Levanta OpenRouterError."""
    models = free_models()
    if not all(is_free_id(m) for m in models):  # trava contra custo
        raise OpenRouterError(400, "modelo pago bloqueado", "paid_model_blocked")
    body = {
        "models": models,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 4000,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": config.OPENROUTER_APP_URL,
        "X-OpenRouter-Title": "CyberPulse",
    }
    started = time.monotonic()
    try:
        with httpx.Client(timeout=config.GEMINI_TIMEOUT_SECONDS) as client:
            resp = client.post(API_URL, json=body, headers=headers)
    except httpx.TimeoutException as exc:
        raise OpenRouterError(504, "timeout", "timeout") from exc
    except httpx.HTTPError as exc:
        raise OpenRouterError(502, type(exc).__name__, "network") from exc

    try:
        data = resp.json()
    except ValueError:
        data = {}

    # Erros podem vir com status HTTP de erro OU com HTTP 200 e "error" no corpo/escolha.
    err = data.get("error") or ((data.get("choices") or [{}])[0].get("error"))
    if resp.status_code >= 400 or err:
        err = err or {}
        status = int(err.get("code") or resp.status_code or 502)
        meta = err.get("metadata") or {}
        raise OpenRouterError(status, str(err.get("message") or resp.text[:200]),
                              str(meta.get("error_type") or ""), _retry_after(resp))

    choice = (data.get("choices") or [{}])[0]
    text = ((choice.get("message") or {}).get("content") or "").strip()
    if not text:
        raise OpenRouterError(502, f"resposta vazia (finish_reason={choice.get('finish_reason')})", "empty")
    model = data.get("model") or models[0]
    logger.info("OpenRouter (gratuito) respondeu com %s em %.1fs", model, time.monotonic() - started)
    return text, model
