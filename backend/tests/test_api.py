from datetime import date
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import ai
from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import Vulnerability
from app.security import ai_limiter


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:
        db = SessionLocal()
        db.add(Vulnerability(cve_id="CVE-2024-3094", title="xz backdoor", source="CISA KEV", known_exploited=True,
                             cvss_score="10.0", cisa_date_added=date(2024, 3, 29), custom_risk_score=8.0))
        db.commit()
        db.close()
        ai_limiter._calls.clear()
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_docs_disabled_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_limit_is_capped(client):
    assert client.get("/api/v1/vulnerabilities?limit=100000").status_code == 422
    assert client.get("/api/v1/vulnerabilities?limit=10").status_code == 200


def test_list_does_not_leak_internal_fields(client):
    item = client.get("/api/v1/vulnerabilities").json()[0]
    assert item["cve_id"] == "CVE-2024-3094"
    assert "ai_analysis" not in item and "_sa_instance_state" not in item
    assert item["has_ai_analysis"] is False


def test_cors_only_allows_configured_origin(client):
    ok = client.get("/health", headers={"Origin": "https://cyberpulse-ochre.vercel.app"})
    bad = client.get("/health", headers={"Origin": "https://evil.example"})
    assert ok.headers.get("access-control-allow-origin") == "https://cyberpulse-ochre.vercel.app"
    assert "access-control-allow-origin" not in bad.headers


def test_security_headers(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_old_public_collect_routes_removed(client):
    assert client.get("/api/v1/collect/cisa").status_code == 404


def test_admin_requires_token(client):
    assert client.post("/api/v1/admin/run/scoring").status_code == 401
    assert client.post("/api/v1/admin/run/scoring", headers={"X-Admin-Token": "wrong"}).status_code == 401
    with patch.dict("app.main.JOBS", {"scoring": lambda: None}):
        r = client.post("/api/v1/admin/run/scoring", headers={"X-Admin-Token": "test-admin-token"})
    assert r.status_code == 200


def test_invalid_cve_path_rejected(client):
    assert client.post("/api/v1/vulnerabilities/not-a-cve/analyze").status_code == 422


def test_analyze_requires_key(client):
    assert client.post("/api/v1/vulnerabilities/CVE-2024-3094/analyze").status_code == 401


def test_analyze_caches_result(client):
    fake = ai.AIResult(text="**O QUE É A VULNERABILIDADE**\nteste", model="m", sources=[{"title": "x", "url": "https://x"}])
    with patch("app.ai.analyze", return_value=fake) as mocked:
        r1 = client.post("/api/v1/vulnerabilities/CVE-2024-3094/analyze", headers={"X-Gemini-Key": "k"})
        r2 = client.post("/api/v1/vulnerabilities/CVE-2024-3094/analyze", headers={"X-Gemini-Key": "k"})
        r3 = client.get("/api/v1/vulnerabilities/CVE-2024-3094/analysis")
    assert r1.status_code == 200 and r1.json()["cached"] is False
    assert r2.json()["cached"] is True
    assert r3.json()["ai_analysis"].startswith("**O QUE")
    assert r3.json()["sources"][0]["url"] == "https://x"
    assert mocked.call_count == 1


def test_analyze_translates_ai_errors(client):
    with patch("app.ai.analyze", side_effect=ai.AIError(429, "COTA_ESGOTADA")):
        r = client.post("/api/v1/vulnerabilities/CVE-2024-3094/analyze", headers={"X-Gemini-Key": "k"})
    assert r.status_code == 429 and r.json()["detail"] == "COTA_ESGOTADA"


def test_ai_rate_limit(client):
    with patch("app.ai.analyze", side_effect=ai.AIError(503, "x")):
        codes = [
            client.post(
                "/api/v1/vulnerabilities/CVE-2024-3094/analyze?force=true",
                headers={"X-Gemini-Key": "k", "X-Forwarded-For": "1.2.3.4"},
            ).status_code
            for _ in range(7)
        ]
    assert codes[:5] == [503] * 5 and codes[5:] == [429, 429]


def test_score_explanation(client):
    body = client.get("/api/v1/vulnerabilities/CVE-2024-3094/score").json()
    assert set(body["components"]) == {"cvss", "epss", "kev", "ransomware", "urgency"}
