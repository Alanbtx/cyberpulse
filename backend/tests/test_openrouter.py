import json
from datetime import date, datetime
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app import ai, config, openrouter
from app.models import Vulnerability

REAL_CLIENT = httpx.Client
GOOD = "**O QUE É A VULNERABILIDADE**\nok\n**COMO VERIFICAR SE VOCÊ ESTÁ VULNERÁVEL**\nx\n**PLANO DE AÇÃO**\ny"

CATALOG = {"data": [
    {"id": "nvidia/nemotron-3-ultra-550b-a55b:free", "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "google/gemma-4-31b-it:free", "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "openrouter/free", "pricing": {"prompt": "0", "completion": "0"}},
    {"id": "anthropic/claude-sonnet-5.5", "pricing": {"prompt": "0.000002", "completion": "0.00001"}},
]}


def _ok_body(model="nvidia/nemotron-3-ultra-550b-a55b:free"):
    return {"model": model, "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": GOOD}}]}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    openrouter._catalog.update(free=None, at=0.0)
    monkeypatch.setattr(config, "OPENROUTER_MODELS",
                        ["nvidia/nemotron-3-ultra-550b-a55b:free", "google/gemma-4-31b-it:free"])


def _mock(monkeypatch, chat_handler, catalog=CATALOG):
    chats = []

    def handler(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json=catalog) if catalog is not None else httpx.Response(500)
        chats.append(request)
        return chat_handler(request)

    monkeypatch.setattr(openrouter.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    return chats


def _vuln():
    return Vulnerability(cve_id="CVE-2024-3094", title="t", source="x", known_exploited=True)


# ---- Nunca gerar custo ----

def test_request_uses_only_free_models_and_no_paid_web_search(monkeypatch):
    chats = _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body()))
    text, model = openrouter.generate("sk-or-teste", "prompt")
    body = json.loads(chats[0].content)
    assert chats[0].headers["Authorization"] == "Bearer sk-or-teste"
    assert body["models"] == ["nvidia/nemotron-3-ultra-550b-a55b:free", "google/gemma-4-31b-it:free", "openrouter/free"]
    assert "plugins" not in body and ":online" not in json.dumps(body)
    assert text == GOOD and model.endswith(":free")


def test_paid_models_in_config_are_ignored(monkeypatch):
    monkeypatch.setattr(config, "OPENROUTER_MODELS", ["anthropic/claude-sonnet-5.5", "google/gemma-4-31b-it:free"])
    chats = _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body()))
    openrouter.generate("k", "p")
    assert json.loads(chats[0].content)["models"] == ["google/gemma-4-31b-it:free", "openrouter/free"]


def test_free_model_removed_from_catalog_is_skipped(monkeypatch):
    catalog = {"data": [m for m in CATALOG["data"] if not m["id"].startswith("nvidia/")]}
    chats = _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body()), catalog=catalog)
    openrouter.generate("k", "p")
    assert json.loads(chats[0].content)["models"] == ["google/gemma-4-31b-it:free", "openrouter/free"]


def test_catalog_offline_still_only_free(monkeypatch):
    monkeypatch.setattr(config, "OPENROUTER_MODELS", ["openai/gpt-5.2", "google/gemma-4-31b-it:free"])
    chats = _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body()), catalog=None)
    openrouter.generate("k", "p")
    assert json.loads(chats[0].content)["models"] == ["google/gemma-4-31b-it:free", "openrouter/free"]


def test_is_free_id():
    assert openrouter.is_free_id("x/y:free") and openrouter.is_free_id("openrouter/free")
    assert not openrouter.is_free_id("openrouter/auto") and not openrouter.is_free_id("google/gemini-3.5-flash")


# ---- Erros e cascata ----

def test_error_inside_http_200_is_detected(monkeypatch):
    _mock(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"error": {"code": 502, "message": "down"}}]}))
    with pytest.raises(openrouter.OpenRouterError) as exc:
        openrouter.generate("k", "p")
    assert exc.value.status == 502


@pytest.mark.parametrize("status,expected,fragment", [
    (401, 401, "CHAVE_INVALIDA_OPENROUTER"),
    (429, 429, "50 análises por dia"),
    (402, 502, "recusou a requisição gratuita"),
    (503, 503, "IA_INDISPONIVEL_OPENROUTER"),
])
def test_errors_are_translated(monkeypatch, status, expected, fragment):
    _mock(monkeypatch, lambda r: httpx.Response(status, json={"error": {"code": status, "message": "x"}}))
    with pytest.raises(ai.AIError) as exc:
        ai.analyze(_vuln(), None, "k")
    assert exc.value.status_code == expected and fragment in exc.value.message
    assert "crédito" not in exc.value.message.lower()


def test_gemini_failure_falls_back_to_openrouter(monkeypatch):
    _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body("google/gemma-4-31b-it:free")))
    with patch("app.ai._analyze_gemini", side_effect=ai.AIError(503, "IA_SOBRECARREGADA")):
        result = ai.analyze(_vuln(), "gemini-key", "or-key")
    assert result.provider == "openrouter" and result.model == "google/gemma-4-31b-it:free"


def test_gemini_success_does_not_touch_openrouter(monkeypatch):
    chats = _mock(monkeypatch, lambda r: httpx.Response(500))
    with patch("app.ai._analyze_gemini", return_value=ai.AIResult("t", "gemini-3.5-flash")):
        assert ai.analyze(_vuln(), "g", "o").model == "gemini-3.5-flash"
    assert chats == []


def test_both_fail_shows_both_reasons(monkeypatch):
    _mock(monkeypatch, lambda r: httpx.Response(429, json={"error": {"code": 429}}))
    with patch("app.ai._analyze_gemini", side_effect=ai.AIError(503, "IA_SOBRECARREGADA")), pytest.raises(ai.AIError) as exc:
        ai.analyze(_vuln(), "g", "o")
    assert "Gemini: IA_SOBRECARREGADA" in exc.value.message and "OpenRouter: COTA_ESGOTADA" in exc.value.message


# ---- Endpoint ----

@pytest.fixture()
def client():
    from app.database import Base, SessionLocal, engine
    from app.main import app
    from app.security import ai_limiter

    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:
        db = SessionLocal()
        db.add(Vulnerability(cve_id="CVE-2024-3094", title="xz", source="CISA KEV", cisa_date_added=date(2024, 3, 29),
                             ai_analysis="análise antiga", ai_analysis_model="gemini-3.5-flash",
                             ai_analysis_at=datetime(2026, 1, 1)))
        db.add(Vulnerability(cve_id="CVE-2024-0001", title="nova", source="CISA KEV"))
        db.commit()
        db.close()
        ai_limiter._calls.clear()
        yield c


def test_endpoint_accepts_openrouter_key_only(client):
    with patch("app.ai.analyze", return_value=ai.AIResult(GOOD, "google/gemma-4-31b-it:free", provider="openrouter")) as m:
        r = client.post("/api/v1/vulnerabilities/CVE-2024-0001/analyze", headers={"X-OpenRouter-Key": "or"})
    assert r.status_code == 200 and r.json()["model"] == "google/gemma-4-31b-it:free"
    assert m.call_args.args[1:] == (None, "or")


def test_endpoint_returns_stale_analysis_when_ai_down(client):
    with patch("app.ai.analyze", side_effect=ai.AIError(503, "IA_SOBRECARREGADA")):
        r = client.post("/api/v1/vulnerabilities/CVE-2024-3094/analyze?force=true", headers={"X-Gemini-Key": "g"})
    body = r.json()
    assert r.status_code == 200 and body["ai_analysis"] == "análise antiga" and body["cached"] is True
    assert "IA_SOBRECARREGADA" in body["warning"]


def test_endpoint_does_not_hide_key_errors_behind_stale(client):
    with patch("app.ai.analyze", side_effect=ai.AIError(401, "CHAVE_INVALIDA_GEMINI")):
        r = client.post("/api/v1/vulnerabilities/CVE-2024-3094/analyze?force=true", headers={"X-Gemini-Key": "g"})
    assert r.status_code == 401


def test_cors_allows_openrouter_header(client):
    r = client.options(
        "/api/v1/vulnerabilities/CVE-2024-0001/analyze",
        headers={"Origin": "https://cyberpulse-ochre.vercel.app", "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "x-openrouter-key"},
    )
    assert r.status_code == 200 and "x-openrouter-key" in r.headers["access-control-allow-headers"].lower()
