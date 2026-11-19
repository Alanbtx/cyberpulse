"""Filtros, ordenação e facetas da listagem de vulnerabilidades."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Literal

from sqlalchemy import case, func, or_
from sqlalchemy.orm import Query, Session

from app.models import Vulnerability

SortKey = Literal["score", "recent", "epss", "due"]
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
PENDING = "PENDING"  # sem nota CVSS ainda


@dataclass
class VulnFilters:
    q: str = ""
    vendor: str | None = None
    severities: list[str] = field(default_factory=list)
    ransomware: bool = False
    due_within_days: int | None = None
    added_within_days: int | None = None
    min_score: float | None = None
    sort: SortKey = "score"

    @property
    def is_plain_search(self) -> bool:
        """Só busca textual, sem filtros extras (usado para decidir a busca em tempo real no NVD)."""
        return not (self.vendor or self.severities or self.ransomware or self.due_within_days
                    or self.added_within_days or self.min_score)


def parse_severities(raw: str | None) -> list[str]:
    if not raw:
        return []
    allowed = set(SEVERITIES) | {PENDING}
    values = {s.strip().upper() for s in raw.split(",")}
    return sorted(values & allowed)


def _escape_like(text: str) -> str:
    return text.replace("%", "").replace("_", "")


def build_query(db: Session, f: VulnFilters, today: date | None = None) -> Query:
    today = today or date.today()
    query = db.query(Vulnerability)

    if f.q:
        search = f"%{_escape_like(f.q)}%"
        query = query.filter(
            Vulnerability.cve_id.ilike(search)
            | Vulnerability.title.ilike(search)
            | Vulnerability.vendor.ilike(search)
            | Vulnerability.product.ilike(search)
        )

    if f.vendor:
        query = query.filter(func.lower(Vulnerability.vendor) == f.vendor.strip().lower())

    if f.severities:
        conds = []
        named = [s for s in f.severities if s != PENDING]
        if named:
            conds.append(func.upper(Vulnerability.severity).in_(named))
        if PENDING in f.severities:
            conds.append(Vulnerability.cvss_score.is_(None))
        query = query.filter(or_(*conds))

    if f.ransomware:
        query = query.filter(Vulnerability.ransomware_use.is_(True))

    if f.due_within_days:
        query = query.filter(
            Vulnerability.cisa_due_date >= today,
            Vulnerability.cisa_due_date <= today + timedelta(days=f.due_within_days),
        )

    if f.added_within_days:
        query = query.filter(Vulnerability.cisa_date_added >= today - timedelta(days=f.added_within_days))

    if f.min_score is not None:
        query = query.filter(Vulnerability.custom_risk_score >= f.min_score)

    order = {
        "recent": (Vulnerability.cisa_date_added.desc().nulls_last(),),
        "epss": (Vulnerability.epss_score.desc().nulls_last(),),
        # Próximos prazos primeiro; vencidos depois (do mais recente ao mais antigo); sem prazo no fim.
        "due": (
            case((Vulnerability.cisa_due_date.is_(None), 2), (Vulnerability.cisa_due_date < today, 1), else_=0),
            case((Vulnerability.cisa_due_date >= today, Vulnerability.cisa_due_date)).asc(),
            Vulnerability.cisa_due_date.desc(),
        ),
        "score": (Vulnerability.custom_risk_score.desc().nulls_last(),),
    }[f.sort]
    # Desempate estável: sem ele a mesma CVE pode aparecer em duas páginas.
    return query.order_by(*order, Vulnerability.id.desc())


def facets(db: Session, today: date | None = None, top_vendors: int = 60) -> dict:
    today = today or date.today()
    vendor_rows = (
        db.query(Vulnerability.vendor, func.count(Vulnerability.id))
        .filter(Vulnerability.vendor.isnot(None))
        .group_by(Vulnerability.vendor)
        .order_by(func.count(Vulnerability.id).desc(), Vulnerability.vendor)
        .limit(top_vendors)
        .all()
    )
    sev_rows = (
        db.query(func.upper(Vulnerability.severity), func.count(Vulnerability.id))
        .filter(Vulnerability.cvss_score.isnot(None))
        .group_by(func.upper(Vulnerability.severity))
        .all()
    )
    severities = {s: 0 for s in SEVERITIES}
    for sev, count in sev_rows:
        if sev in severities:
            severities[sev] = count
    severities[PENDING] = db.query(func.count(Vulnerability.id)).filter(Vulnerability.cvss_score.is_(None)).scalar()

    return {
        "total": db.query(func.count(Vulnerability.id)).scalar(),
        "vendors": [{"name": v, "count": c} for v, c in vendor_rows],
        "severities": severities,
        "ransomware": db.query(func.count(Vulnerability.id)).filter(Vulnerability.ransomware_use.is_(True)).scalar(),
        "due_14_days": db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.cisa_due_date >= today, Vulnerability.cisa_due_date <= today + timedelta(days=14)
        ).scalar(),
        "added_30_days": db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.cisa_date_added >= today - timedelta(days=30)
        ).scalar(),
    }
