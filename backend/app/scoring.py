"""Motor de priorização de risco do CyberPulse (nota de 0 a 10).

A versão anterior dava +4 pontos a toda vulnerabilidade do catálogo KEV (ou seja,
a todas) e usava CVSS 5.0 quando o NVD ainda não tinha respondido, sem nunca
recalcular. Resultado: ~95% das CVEs ficavam entre 7 e 8.

Agora a nota combina sinais que realmente diferenciam:

  componente           peso   origem
  -------------------  -----  ------------------------------------------------
  Severidade (CVSS)    35%    NVD (v4.0 > v3.1 > v3.0 > v2)
  Probabilidade (EPSS) 25%    FIRST.org, raiz quadrada para espalhar valores baixos
  Exploração ativa     15%    CISA KEV
  Ransomware           10%    campo knownRansomwareCampaignUse do KEV
  Urgência             15%    recência (meia-vida ~60 dias) ou prazo CISA vencendo

A nota é recalculada periodicamente, então a urgência decai com o tempo e
dados que chegam depois (CVSS, EPSS) passam a contar.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date

WEIGHTS = {
    "cvss": 0.35,
    "epss": 0.25,
    "kev": 0.15,
    "ransomware": 0.10,
    "urgency": 0.15,
}

UNKNOWN_CVSS = 6.0   # valor neutro-alto: KEV sem CVSS ainda é algo explorado
UNKNOWN_EPSS = 0.05
RECENCY_HALF_LIFE_DAYS = 60


@dataclass
class ScoreInput:
    cvss_score: str | float | None = None
    known_exploited: bool = False
    ransomware_use: bool | None = None
    epss_score: float | None = None
    cisa_date_added: date | None = None
    cisa_due_date: date | None = None
    published_at: date | None = None


def _parse_cvss(value) -> float | None:
    if value in (None, "", "None"):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return min(max(v, 0.0), 10.0)


def _urgency(inp: ScoreInput, today: date) -> float:
    reference = inp.cisa_date_added or inp.published_at
    recency = 0.0
    if reference:
        age = max((today - reference).days, 0)
        recency = 0.5 ** (age / RECENCY_HALF_LIFE_DAYS)

    deadline = 0.0
    if inp.cisa_due_date:
        days_left = (inp.cisa_due_date - today).days
        if 0 <= days_left <= 14:
            deadline = 1.0 - days_left / 28  # 1.0 no dia, 0.5 a duas semanas
    return max(recency, deadline)


def score_components(inp: ScoreInput, today: date | None = None) -> dict[str, float]:
    today = today or date.today()
    cvss = _parse_cvss(inp.cvss_score)
    epss = inp.epss_score if inp.epss_score is not None else UNKNOWN_EPSS
    return {
        "cvss": (cvss if cvss is not None else UNKNOWN_CVSS) / 10,
        "epss": math.sqrt(min(max(epss, 0.0), 1.0)),
        "kev": 1.0 if inp.known_exploited else 0.0,
        "ransomware": 1.0 if inp.ransomware_use else 0.0,
        "urgency": _urgency(inp, today),
    }


def calculate_risk_score(inp: ScoreInput, today: date | None = None) -> float:
    parts = score_components(inp, today)
    total = sum(WEIGHTS[k] * v for k, v in parts.items()) * 10
    return round(min(max(total, 0.0), 10.0), 1)


def score_vulnerability(vuln, today: date | None = None) -> float:
    return calculate_risk_score(
        ScoreInput(
            cvss_score=vuln.cvss_score,
            known_exploited=bool(vuln.known_exploited),
            ransomware_use=vuln.ransomware_use,
            epss_score=vuln.epss_score,
            cisa_date_added=vuln.cisa_date_added,
            cisa_due_date=vuln.cisa_due_date,
            published_at=vuln.published_at,
        ),
        today,
    )
