from datetime import date, timedelta

from app.scoring import ScoreInput, calculate_risk_score

TODAY = date(2026, 11, 18)


def score(**kw):
    return calculate_risk_score(ScoreInput(**kw), today=TODAY)


def test_score_range():
    assert 0 <= score() <= 10
    top = score(cvss_score="10.0", known_exploited=True, ransomware_use=True, epss_score=1.0, cisa_date_added=TODAY)
    assert top == 10.0


def test_higher_cvss_means_higher_score():
    base = dict(known_exploited=True, epss_score=0.2, cisa_date_added=TODAY - timedelta(days=400))
    assert score(cvss_score="9.9", **base) > score(cvss_score="5.5", **base)


def test_kev_items_are_differentiated():
    """Regressão: antes quase todo KEV ficava entre 7 e 8."""
    old_low = score(cvss_score="5.5", known_exploited=True, epss_score=0.01, cisa_date_added=TODAY - timedelta(days=900))
    new_critical = score(cvss_score="9.8", known_exploited=True, ransomware_use=True, epss_score=0.9, cisa_date_added=TODAY - timedelta(days=3))
    assert new_critical - old_low >= 4


def test_recency_decays():
    common = dict(cvss_score="8.0", known_exploited=True, epss_score=0.3)
    assert (
        score(cisa_date_added=TODAY, **common)
        > score(cisa_date_added=TODAY - timedelta(days=60), **common)
        > score(cisa_date_added=TODAY - timedelta(days=365), **common)
    )


def test_cisa_deadline_raises_urgency():
    common = dict(cvss_score="8.0", known_exploited=True, epss_score=0.3, cisa_date_added=TODAY - timedelta(days=365))
    assert score(cisa_due_date=TODAY + timedelta(days=2), **common) > score(**common)


def test_invalid_cvss_does_not_crash():
    assert 0 <= score(cvss_score="abc") <= 10
    assert 0 <= score(cvss_score="None") <= 10
