"""Coleta do EPSS (Exploit Prediction Scoring System) da FIRST.org.

O EPSS estima a probabilidade de uma CVE ser explorada nos próximos 30 dias.
API pública e gratuita, aceita várias CVEs por requisição.
"""
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import Vulnerability

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100


def fetch_and_save_epss(db: Session, max_age_hours: int = 20):
    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
    vulns = (
        db.query(Vulnerability)
        .filter(or_(Vulnerability.epss_updated_at.is_(None), Vulnerability.epss_updated_at < cutoff))
        .all()
    )
    if not vulns:
        return {"status": "success", "atualizadas": 0}

    by_id = {v.cve_id: v for v in vulns}
    ids = list(by_id)
    updated = 0
    now = datetime.utcnow()

    with httpx.Client(timeout=30.0) as client:
        for i in range(0, len(ids), BATCH_SIZE):
            batch = ids[i:i + BATCH_SIZE]
            try:
                resp = client.get(EPSS_URL, params={"cve": ",".join(batch), "limit": BATCH_SIZE})
                resp.raise_for_status()
                rows = resp.json().get("data", [])
            except (httpx.HTTPError, ValueError) as e:
                logger.warning("Falha no EPSS (lote %s): %s", i // BATCH_SIZE, type(e).__name__)
                continue
            found = set()
            for row in rows:
                vuln = by_id.get(row.get("cve"))
                if not vuln:
                    continue
                try:
                    vuln.epss_score = float(row["epss"])
                    vuln.epss_percentile = float(row["percentile"])
                except (KeyError, TypeError, ValueError):
                    continue
                vuln.epss_updated_at = now
                found.add(vuln.cve_id)
                updated += 1
            # CVEs sem EPSS publicado: marca a tentativa para não repetir a cada execução.
            for cve_id in batch:
                if cve_id not in found:
                    by_id[cve_id].epss_updated_at = now
            db.commit()

    logger.info("EPSS atualizado para %s CVEs.", updated)
    return {"status": "success", "atualizadas": updated}
