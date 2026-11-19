from datetime import date, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models import Vulnerability

TODAY = date.today()


def _v(cve, **kw):
    base = dict(cve_id=cve, title=cve, source="CISA KEV", known_exploited=True)
    base.update(kw)
    return Vulnerability(**base)


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:
        db = SessionLocal()
        db.add_all([
            _v("CVE-2024-0001", vendor="Microsoft", severity="CRITICAL", cvss_score="9.8", custom_risk_score=8.5,
               ransomware_use=True, epss_score=0.9, cisa_date_added=TODAY - timedelta(days=3),
               cisa_due_date=TODAY + timedelta(days=5)),
            _v("CVE-2024-0002", vendor="microsoft", severity="HIGH", cvss_score="7.5", custom_risk_score=6.0,
               ransomware_use=False, epss_score=0.2, cisa_date_added=TODAY - timedelta(days=200),
               cisa_due_date=TODAY - timedelta(days=150)),
            _v("CVE-2024-0003", vendor="Fortinet", severity=None, cvss_score=None, custom_risk_score=5.0,
               ransomware_use=True, epss_score=0.5, cisa_date_added=TODAY - timedelta(days=10),
               cisa_due_date=TODAY + timedelta(days=30)),
        ] + [
            _v(f"CVE-2023-{1000 + i}", vendor="Cisco", severity="MEDIUM", cvss_score="5.0",
               custom_risk_score=3.0, cisa_date_added=TODAY - timedelta(days=400))
            for i in range(30)
        ])
        db.commit()
        db.close()
        yield c


def ids(resp):
    return [v["cve_id"] for v in resp.json()["items"]]


def test_pagination_totals_and_no_overlap(client):
    p1 = client.get("/api/v1/vulnerabilities/search?page_size=10&page=1").json()
    p4 = client.get("/api/v1/vulnerabilities/search?page_size=10&page=4").json()
    assert p1["total"] == 33 and p1["pages"] == 4
    assert len(p1["items"]) == 10 and len(p4["items"]) == 3
    seen = []
    for page in range(1, 5):
        seen += ids(client.get(f"/api/v1/vulnerabilities/search?page_size=10&page={page}"))
    assert len(seen) == len(set(seen)) == 33


def test_page_size_capped(client):
    assert client.get("/api/v1/vulnerabilities/search?page_size=500").status_code == 422


def test_vendor_filter_is_case_insensitive(client):
    assert sorted(ids(client.get("/api/v1/vulnerabilities/search?vendor=MICROSOFT"))) == ["CVE-2024-0001", "CVE-2024-0002"]


def test_severity_filter_with_pending(client):
    r = client.get("/api/v1/vulnerabilities/search?severity=critical,PENDING,bogus")
    assert sorted(ids(r)) == ["CVE-2024-0001", "CVE-2024-0003"]


def test_ransomware_filter(client):
    assert sorted(ids(client.get("/api/v1/vulnerabilities/search?ransomware=true"))) == ["CVE-2024-0001", "CVE-2024-0003"]


def test_due_within_days_ignores_overdue(client):
    assert ids(client.get("/api/v1/vulnerabilities/search?due_within_days=14")) == ["CVE-2024-0001"]


def test_added_within_days(client):
    assert sorted(ids(client.get("/api/v1/vulnerabilities/search?added_within_days=30"))) == ["CVE-2024-0001", "CVE-2024-0003"]


def test_min_score(client):
    assert ids(client.get("/api/v1/vulnerabilities/search?min_score=8")) == ["CVE-2024-0001"]


def test_combined_filters(client):
    r = client.get("/api/v1/vulnerabilities/search?ransomware=true&vendor=fortinet")
    assert ids(r) == ["CVE-2024-0003"]


def test_sorts(client):
    assert ids(client.get("/api/v1/vulnerabilities/search?sort=epss&page_size=3")) == ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]
    assert ids(client.get("/api/v1/vulnerabilities/search?sort=recent&page_size=1")) == ["CVE-2024-0001"]
    # Próximo prazo primeiro (+5 dias), depois +30; vencidos depois.
    assert ids(client.get("/api/v1/vulnerabilities/search?sort=due&page_size=3")) == ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]
    assert client.get("/api/v1/vulnerabilities/search?sort=drop_table").status_code == 422


def test_facets(client):
    body = client.get("/api/v1/vulnerabilities/facets").json()
    assert body["total"] == 33
    assert body["vendors"][0] == {"name": "Cisco", "count": 30}
    assert body["severities"]["PENDING"] == 1 and body["severities"]["CRITICAL"] == 1
    assert body["ransomware"] == 2 and body["due_14_days"] == 1 and body["added_30_days"] == 2


def test_realtime_nvd_only_for_plain_search(client):
    with patch("app.main.fetch_new_cve", return_value={"status": "error"}) as nvd:
        client.get("/api/v1/vulnerabilities/search?q=CVE-2099-9999&ransomware=true")
        assert nvd.call_count == 0
        client.get("/api/v1/vulnerabilities/search?q=CVE-2099-9999")
        assert nvd.call_count == 1


def test_legacy_list_still_returns_array_with_filters(client):
    r = client.get("/api/v1/vulnerabilities?vendor=fortinet")
    assert isinstance(r.json(), list) and [v["cve_id"] for v in r.json()] == ["CVE-2024-0003"]
