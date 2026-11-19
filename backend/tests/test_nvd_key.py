"""Cenário de produção: NVD_API_KEY inválida faz o NVD responder 404 "Invalid apiKey"."""
import httpx
import pytest

from app import config
from app.collectors import nvd

REAL_CLIENT = httpx.Client
CVE_JSON = {"vulnerabilities": [{"cve": {"id": "CVE-2024-10441", "metrics": {}}}]}


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    monkeypatch.setattr(nvd, "_key_rejected", False)
    monkeypatch.setattr(nvd, "_throttle", lambda: None)
    monkeypatch.setattr(config, "NVD_API_KEY", "chave-errada")


def _transport(monkeypatch, handler):
    calls = []

    def wrapped(request):
        calls.append(request.headers.get("apiKey"))
        return handler(request)

    monkeypatch.setattr(nvd.httpx, "Client", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(wrapped), **kw))
    return calls


def test_invalid_key_falls_back_to_no_key(monkeypatch):
    def handler(request):
        if request.headers.get("apiKey"):
            return httpx.Response(404, headers={"message": "Invalid apiKey."})
        return httpx.Response(200, json=CVE_JSON)

    calls = _transport(monkeypatch, handler)
    assert nvd._fetch_nvd("CVE-2024-10441")["id"] == "CVE-2024-10441"
    assert nvd.key_active() is False
    # Próximas chamadas já vão sem a chave.
    nvd._fetch_nvd("CVE-2024-10441")
    assert calls == ["chave-errada", None, None]


def test_valid_key_is_kept(monkeypatch):
    calls = _transport(monkeypatch, lambda r: httpx.Response(200, json=CVE_JSON))
    nvd._fetch_nvd("CVE-2024-10441")
    assert calls == ["chave-errada"] and nvd.key_active() is True


def test_failed_cve_is_marked_checked_so_job_moves_on(monkeypatch):
    from datetime import date

    from fastapi.testclient import TestClient

    from app.database import Base, SessionLocal, engine
    from app.jobs import run_nvd_enrichment_job
    from app.main import app
    from app.models import Vulnerability

    Base.metadata.drop_all(bind=engine)
    with TestClient(app):
        db = SessionLocal()
        db.add_all([
            Vulnerability(cve_id="CVE-2024-0001", title="a", source="x", cisa_date_added=date(2024, 2, 1)),
            Vulnerability(cve_id="CVE-2024-0002", title="b", source="x", cisa_date_added=date(2024, 1, 1)),
        ])
        db.commit()
        db.close()

        seen = []

        def handler(request):
            seen.append(request.url.params["cveId"])
            return httpx.Response(500)

        _transport(monkeypatch, handler)
        run_nvd_enrichment_job()
        run_nvd_enrichment_job()
    # Antes ficava repetindo CVE-2024-0001 para sempre.
    assert seen == ["CVE-2024-0001", "CVE-2024-0002"]
