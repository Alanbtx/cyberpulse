"""Provedor reserva: OpenRouter (https://openrouter.ai), com a chave do próprio usuário.

Para manter a mesma qualidade do Gemini:
- A lista começa pelo MESMO modelo do Gemini (servido pelo OpenRouter) e segue para
  modelos de primeira linha de outra empresa. O OpenRouter troca de modelo sozinho
  quando um falha (parâmetro `models`).
- Busca na web ligada (plugin "web"), com as fontes devolvidas como citações.
- Modelos gratuitos (":free") ficam DESLIGADOS por padrão: são sorteados entre modelos
  menores e têm limite de 50 pedidos/dia.
"""
from __future__ import annotations

import logging
import time

import httpx

from app import config

logger = logging.getLogger(__name__)

API_URL = "https://openrouter.ai/api/v1/chat/completions"
SYSTEM_PROMPT = (
    "Você é um analista sênior de inteligência de ameaças. Use a busca na web para confirmar "
    "KBs, versões e correções oficiais. Siga exatamente o formato pedido pelo usuário."
)


class OpenRouterError(Exception):
    def __init__(self, status: int, message: str, error_type: str = "", retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.error_type = error_type
        self.retry_after = retry_after


def _sources(message: dict) -> list[dict]:
    out, seen = [], set()
    for ann in message.get("annotations") or []:
        cite = ann.get("url_citation") or {}
        url = cite.get("url") or ""
        if ann.get("type") == "url_citation" and url.startswith("https://") and url not in seen:
            seen.add(url)
            out.append({"title": (cite.get("title") or url)[:200], "url": url})
    return out[:8]


def _retry_after(resp: httpx.Response) -> int | None:
    try:
        return int(float(resp.headers.get("retry-after", "")))
    except ValueError:
        return None


def generate(api_key: str, prompt: str, use_search: bool = True) -> tuple[str, str, list[dict]]:
    """Devolve (texto, modelo_que_respondeu, fontes). Levanta OpenRouterError."""
    models = list(config.OPENROUTER_MODELS)
    if config.OPENROUTER_FREE_FALLBACK:
        models.append("openrouter/free")
    body: dict = {
        # O OpenRouter aceita no máximo alguns modelos em `models`; o primeiro é o preferido.
        "models": models[:3],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 4000,
    }
    if use_search:
        body["plugins"] = [{"id": "web", "max_results": 5}]

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
    message = choice.get("message") or {}
    text = (message.get("content") or "").strip()
    if not text:
        raise OpenRouterError(502, f"resposta vazia (finish_reason={choice.get('finish_reason')})", "empty")
    model = data.get("model") or models[0]
    logger.info("OpenRouter respondeu com %s em %.1fs", model, time.monotonic() - started)
    return text, model, _sources(message)
