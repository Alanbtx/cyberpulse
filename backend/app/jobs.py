"""Rotinas de coleta e processamento (rodam no APScheduler ou via rota admin/cron)."""
import logging
import threading
import time
from datetime import datetime, timedelta

from deep_translator import GoogleTranslator
from sqlalchemy import and_, or_

from app import config
from app.collectors.cisa_kev import fetch_and_save_cisa_kev
from app.collectors.epss import fetch_and_save_epss
from app.collectors.feeds import fetch_and_save_feeds
from app.collectors.nvd import enrich_cve_with_nvd
from app.database import SessionLocal
from app.models import Advisory, Vulnerability
from app.scoring import score_vulnerability

logger = logging.getLogger(__name__)

# Quanto tempo esperar antes de perguntar de novo ao NVD por uma CVE ainda sem CVSS.
NVD_RECHECK_AFTER = timedelta(days=1)

# Impede que o mesmo job rode em paralelo (agendador + chamada manual).
_locks: dict[str, threading.Lock] = {}


def _exclusive(name):
    lock = _locks.setdefault(name, threading.Lock())

    def decorator(fn):
        def wrapper(*args, **kwargs):
            if not lock.acquire(blocking=False):
                logger.info("Job %s já está rodando; ignorando.", name)
                return {"status": "skipped"}
            db = SessionLocal()
            try:
                return fn(db, *args, **kwargs)
            except Exception:
                db.rollback()
                logger.exception("Erro no job %s", name)
                return {"status": "error"}
            finally:
                db.close()
                lock.release()
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


@_exclusive("nvd")
def run_nvd_enrichment_job(db, batch: int = 1):
    """Enriquece CVEs nunca verificadas e, depois, as que seguem sem CVSS há mais de 1 dia."""
    retry_before = datetime.utcnow() - NVD_RECHECK_AFTER
    vulns = (
        db.query(Vulnerability)
        .filter(or_(
            Vulnerability.nvd_checked_at.is_(None),
            and_(Vulnerability.cvss_score.is_(None), Vulnerability.nvd_checked_at < retry_before),
        ))
        .order_by(Vulnerability.nvd_checked_at.asc().nulls_first(), Vulnerability.cisa_date_added.desc().nulls_last())
        .limit(batch)
        .all()
    )
    # Sem chave o NVD aceita 5 req/30s; com chave, 50 req/30s.
    pause = 0.7 if config.NVD_API_KEY else 6.5
    for i, v in enumerate(vulns):
        if i:
            time.sleep(pause)
        enrich_cve_with_nvd(db, v.cve_id)
    return {"status": "success", "processadas": len(vulns)}


@_exclusive("feeds")
def run_feeds_job(db):
    return fetch_and_save_feeds(db)


@_exclusive("cisa")
def run_cisa_job(db):
    return fetch_and_save_cisa_kev(db)


@_exclusive("epss")
def run_epss_job(db):
    return fetch_and_save_epss(db)


@_exclusive("scoring")
def run_scoring_job(db):
    """Recalcula a nota de todas as CVEs (a urgência decai com o tempo e dados novos chegam)."""
    now = datetime.utcnow()
    count = 0
    for vuln in db.query(Vulnerability).yield_per(500):
        new_score = score_vulnerability(vuln)
        if vuln.custom_risk_score != new_score:
            vuln.custom_risk_score = new_score
            vuln.score_updated_at = now
            count += 1
    db.commit()
    return {"status": "success", "alteradas": count}


def _translate(translator, text):
    return translator.translate(text[:4900]) if text else text


@_exclusive("translate")
def run_translation_job(db):
    translator = GoogleTranslator(source="auto", target="pt")

    adv = db.query(Advisory).filter(Advisory.title_pt.is_(None)).order_by(Advisory.published_at.desc().nulls_last()).first()
    if adv:
        try:
            adv.title_pt = _translate(translator, adv.title) or adv.title
            adv.description_pt = _translate(translator, adv.description) or adv.description
        except Exception as e:
            logger.warning("Falha ao traduzir advisory %s: %s", adv.id, type(e).__name__)
            adv.title_pt, adv.description_pt = adv.title, adv.description
        db.commit()
        return {"status": "success"}

    vuln = db.query(Vulnerability).filter(Vulnerability.title_pt.is_(None)).order_by(Vulnerability.cisa_date_added.desc().nulls_last()).first()
    if vuln:
        try:
            vuln.title_pt = _translate(translator, vuln.title) or vuln.title
            vuln.description_pt = _translate(translator, vuln.description) or vuln.description
            vuln.cisa_required_action_pt = _translate(translator, vuln.cisa_required_action) or vuln.cisa_required_action
        except Exception as e:
            logger.warning("Falha ao traduzir %s: %s", vuln.cve_id, type(e).__name__)
            vuln.title_pt, vuln.description_pt = vuln.title, vuln.description
            vuln.cisa_required_action_pt = vuln.cisa_required_action
        db.commit()
    return {"status": "success"}


def run_full_refresh():
    """Coleta completa: usada no boot e pelo cron externo."""
    return {
        "cisa": run_cisa_job(),
        "feeds": run_feeds_job(),
        "epss": run_epss_job(),
        "scoring": run_scoring_job(),
    }


JOBS = {
    "cisa": run_cisa_job,
    "feeds": run_feeds_job,
    "epss": run_epss_job,
    "scoring": run_scoring_job,
    "nvd": lambda: run_nvd_enrichment_job(batch=20),
    "all": run_full_refresh,
}
