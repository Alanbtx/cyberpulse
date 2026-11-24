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


def _ok_body(model="google/gemini-3.5-flash"):
    return {
        "model": model,
        "choices": [{"finish_reason": "stop", "message": {
            "role": "assistant", "content": GOOD,
            "annotations": [
                {"type": "url_citation", "url_citation": {"url": "https://msrc.microsoft.com/x", "title": "MSRC"}},
                {"type": "url_citation", "url_citation": {"url": "http://inseguro.example", "title": "http"}},
            ],
        }}],
    }


def _mock(monkeypatch, handler):
    requests = []

    def wrapped(request):
        requests.append(request)
        return handler(request)

    monkeypatch.setattr(openrouter.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(wrapped), **kw))
    return requests


def _vuln():
    return Vulnerability(cve_id="CVE-2024-3094", title="t", source="x", known_exploited=True)


def test_request_shape_and_parsing(monkeypatch):
    reqs = _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body()))
    text, model, sources = openrouter.generate("sk-or-teste", "prompt")
    body = json.loads(reqs[0].content)
    assert reqs[0].headers["Authorization"] == "Bearer sk-or-teste"
    assert body["models"] == ["google/gemini-3.5-flash", "anthropic/claude-sonnet-5.5"]
    assert body["plugins"] == [{"id": "web", "max_results": 5}]
    assert not any(m.endswith(":free") or m == "openrouter/free" for m in body["models"])
    assert text == GOOD and model == "google/gemini-3.5-flash"
    assert sources == [{"title": "MSRC", "url": "https://msrc.microsoft.com/x"}]  # só https


def test_error_inside_http_200_is_detected(monkeypatch):
    _mock(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"error": {"code": 502, "message": "down"}}]}))
    with pytest.raises(openrouter.OpenRouterError) as exc:
        openrouter.generate("k", "p")
    assert exc.value.status == 502


@pytest.mark.parametrize("status,expected,fragment", [
    (401, 401, "CHAVE_INVALIDA_OPENROUTER"),
    (402, 402, "SEM_CREDITOS_OPENROUTER"),
    (429, 429, "COTA_ESGOTADA_OPENROUTER"),
    (503, 503, "IA_INDISPONIVEL_OPENROUTER"),
])
def test_errors_are_translated(monkeypatch, status, expected, fragment):
    _mock(monkeypatch, lambda r: httpx.Response(status, json={"error": {"code": status, "message": "x"}}))
    with pytest.raises(ai.AIError) as exc:
        ai.analyze(_vuln(), None, "k")
    assert exc.value.status_code == expected and fragment in exc.value.message


def test_retries_without_web_search_on_provider_error(monkeypatch):
    calls = []

    def handler(request):
        calls.append("plugins" in json.loads(request.content))
        return httpx.Response(502, json={"error": {"code": 502}}) if len(calls) == 1 else httpx.Response(200, json=_ok_body())

    _mock(monkeypatch, handler)
    assert ai.analyze(_vuln(), None, "k").provider == "openrouter"
    assert calls == [True, False]


def test_gemini_overloaded_falls_back_to_openrouter_without_lite_models(monkeypatch):
    _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body("anthropic/claude-sonnet-5.5")))
    with patch("app.ai._analyze_gemini", side_effect=ai.AIError(503, "IA_SOBRECARREGADA")) as gem:
        result = ai.analyze(_vuln(), "gemini-key", "or-key")
    assert result.provider == "openrouter" and result.model == "anthropic/claude-sonnet-5.5"
    assert gem.call_args.kwargs["use_fallback_models"] is False


def test_gemini_only_keeps_reserve_models():
    with patch("app.ai._analyze_gemini", return_value=ai.AIResult("t", "m")) as gem:
        ai.analyze(_vuln(), "gemini-key", None)
    assert gem.call_args.kwargs["use_fallback_models"] is True


def test_both_fail_shows_both_reasons(monkeypatch):
    _mock(monkeypatch, lambda r: httpx.Response(402, json={"error": {"code": 402}}))
    with patch("app.ai._analyze_gemini", side_effect=ai.AIError(503, "IA_SOBRECARREGADA")), pytest.raises(ai.AIError) as exc:
        ai.analyze(_vuln(), "g", "o")
    assert exc.value.status_code == 402
    assert "Gemini: IA_SOBRECARREGADA" in exc.value.message and "OpenRouter: SEM_CREDITOS" in exc.value.message


def test_free_models_only_when_enabled(monkeypatch):
    monkeypatch.setattr(config, "OPENROUTER_MODELS", ["google/gemini-3.5-flash"])
    monkeypatch.setattr(config, "OPENROUTER_FREE_FALLBACK", True)
    reqs = _mock(monkeypatch, lambda r: httpx.Response(200, json=_ok_body()))
    openrouter.generate("k", "p")
    assert json.loads(reqs[0].content)["models"] == ["google/gemini-3.5-flash", "openrouter/free"]


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
    with patch("app.ai.analyze", return_value=ai.AIResult(GOOD, "anthropic/claude-sonnet-5.5", provider="openrouter")) as m:
        r = client.post("/api/v1/vulnerabilities/CVE-2024-0001/analyze", headers={"X-OpenRouter-Key": "or"})
    assert r.status_code == 200 and r.json()["model"] == "anthropic/claude-sonnet-5.5"
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
