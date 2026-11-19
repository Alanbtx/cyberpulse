"""Cenário real dos logs de produção: busca -> 429, modelo principal -> 503."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from google.genai import errors

from app import ai, config
from app.models import Vulnerability


def _vuln():
    return Vulnerability(cve_id="CVE-2024-3094", title="t", source="x", known_exploited=True)


def _ok(text="**O QUE É A VULNERABILIDADE**\nok"):
    r = MagicMock()
    r.text = text
    r.candidates = []
    return r


def quota(delay="37s"):
    return errors.ClientError(429, {"error": {"code": 429, "message": "Quota exceeded", "status": "RESOURCE_EXHAUSTED",
                                              "details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": delay}]}})


def overloaded():
    return errors.ServerError(503, {"error": {"code": 503, "message": "The model is overloaded.", "status": "UNAVAILABLE"}})


MODEL_LIST = [
    SimpleNamespace(name="models/gemini-3.5-flash", supported_actions=["generateContent"]),
    SimpleNamespace(name="models/gemini-3.5-flash-lite", supported_actions=["generateContent"]),
    SimpleNamespace(name="models/gemini-2.5-flash", supported_actions=["generateContent"]),
    SimpleNamespace(name="models/gemini-3.5-pro", supported_actions=["generateContent"]),
    SimpleNamespace(name="models/gemini-3.6-flash-preview", supported_actions=["generateContent"]),
    SimpleNamespace(name="models/gemini-3.5-flash-tts", supported_actions=["generateContent"]),
    SimpleNamespace(name="models/text-embedding-005", supported_actions=["embedContent"]),
]


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    ai._fallback_cache.update(models=None, at=0.0)
    monkeypatch.setattr(config, "GEMINI_MODEL", "gemini-3.5-flash")
    monkeypatch.setattr(config, "GEMINI_FALLBACK_MODEL", "")
    monkeypatch.setattr(config, "GEMINI_USE_SEARCH", True)


def _client(side_effect):
    client = MagicMock()
    client.models.generate_content.side_effect = side_effect
    client.models.list.return_value = MODEL_LIST
    return client


def _models_called(client):
    return [(c.kwargs["model"], c.kwargs["config"].tools is not None) for c in client.models.generate_content.call_args_list]


def test_pick_fallback_models():
    names = [m.name.removeprefix("models/") for m in MODEL_LIST]
    assert ai.pick_fallback_models(names, "gemini-3.5-flash") == ["gemini-3.5-flash-lite", "gemini-2.5-flash"]


def test_search_quota_falls_back_to_no_search_immediately():
    client = _client([quota(), _ok()])
    with patch("app.ai._client", return_value=client):
        result = ai.analyze(_vuln(), "k")
    assert _models_called(client) == [("gemini-3.5-flash", True), ("gemini-3.5-flash", False)]
    assert result.model == "gemini-3.5-flash" and result.sources == []


def test_production_scenario_uses_fallback_model():
    client = _client([quota(), overloaded(), _ok()])
    with patch("app.ai._client", return_value=client):
        result = ai.analyze(_vuln(), "k")
    assert result.model == "gemini-3.5-flash-lite"
    assert _models_called(client) == [
        ("gemini-3.5-flash", True), ("gemini-3.5-flash", False), ("gemini-3.5-flash-lite", False),
    ]


def test_everything_overloaded_reports_overload_not_search_quota():
    client = _client([quota(), overloaded(), overloaded(), overloaded()])
    with patch("app.ai._client", return_value=client), pytest.raises(ai.AIError) as exc:
        ai.analyze(_vuln(), "k")
    assert exc.value.status_code == 503
    assert client.models.generate_content.call_count == 4  # busca, principal, 2 reservas


def test_quota_everywhere_reports_wait_time():
    client = _client([quota(), quota("12s"), quota(), quota()])
    with patch("app.ai._client", return_value=client), pytest.raises(ai.AIError) as exc:
        ai.analyze(_vuln(), "k")
    assert exc.value.status_code == 429
    assert "12 segundos" in exc.value.message


def test_fallback_list_is_cached():
    client = _client([quota(), overloaded(), _ok(), quota(), overloaded(), _ok()])
    with patch("app.ai._client", return_value=client):
        ai.analyze(_vuln(), "k")
        ai.analyze(_vuln(), "k")
    assert client.models.list.call_count == 1


def test_configured_fallback_skips_discovery(monkeypatch):
    monkeypatch.setattr(config, "GEMINI_FALLBACK_MODEL", "meu-modelo")
    client = _client([quota(), overloaded(), _ok()])
    with patch("app.ai._client", return_value=client):
        assert ai.analyze(_vuln(), "k").model == "meu-modelo"
    client.models.list.assert_not_called()


def test_sdk_does_not_retry_quota_errors():
    retry = ai._client("k")._api_client._http_options.retry_options
    assert 429 not in retry.http_status_codes and 503 in retry.http_status_codes
