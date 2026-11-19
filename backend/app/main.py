import json
import logging
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Literal

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app import ai, config
from app.collectors.nvd import fetch_new_cve, is_valid_cve_id
from app.database import get_db, run_migrations
from app.jobs import (
    JOBS,
    run_full_refresh,
    run_nvd_enrichment_job,
    run_scoring_job,
    run_translation_job,
    run_feeds_job,
    run_cisa_job,
    run_epss_job,
)
from app.models import Advisory, Vulnerability
from app.scoring import WEIGHTS, ScoreInput, score_components
from app.security import SecurityHeadersMiddleware, ai_limiter, require_admin, search_limiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler(job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 60})
scheduler.add_job(run_nvd_enrichment_job, "interval", seconds=3 if config.NVD_API_KEY else 7, id="nvd_job")
scheduler.add_job(run_translation_job, "interval", seconds=5, id="translate_job")
scheduler.add_job(run_scoring_job, "interval", minutes=30, id="scoring_job")
scheduler.add_job(run_feeds_job, "interval", minutes=30, id="feeds_job")
scheduler.add_job(run_cisa_job, "interval", hours=6, id="cisa_job")
scheduler.add_job(run_epss_job, "interval", hours=12, id="epss_job")


@asynccontextmanager
async def lifespan(app: FastAPI):
    run_migrations()
    if config.ENABLE_SCHEDULER:
        scheduler.start()
        # Coleta inicial em segundo plano: a API sobe na hora, sem esperar CISA/EPSS.
        threading.Thread(target=run_full_refresh, name="initial-refresh", daemon=True).start()
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="CyberPulse API",
    description="API para a Plataforma Aberta de Inteligência em Segurança",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_origin_regex=config.CORS_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Gemini-Key"],
    max_age=600,
)

CveId = Path(..., pattern=r"^CVE-\d{4}-\d{4,7}$", max_length=20)

_VULN_FIELDS = (
    "id", "cve_id", "title", "description", "severity", "cvss_score", "cvss_vector", "vendor", "product",
    "known_exploited", "ransomware_use", "epss_score", "epss_percentile", "cisa_date_added",
    "cisa_required_action", "cisa_due_date", "published_at", "custom_risk_score", "source",
)


def _vuln_to_dict(v: Vulnerability, lang: str) -> dict:
    data = {f: getattr(v, f) for f in _VULN_FIELDS}
    if lang == "pt-br":
        data["title"] = v.title_pt or v.title
        data["description"] = v.description_pt or v.description
        data["cisa_required_action"] = v.cisa_required_action_pt or v.cisa_required_action
    data["has_ai_analysis"] = bool(v.ai_analysis)
    return data


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/api/v1/vulnerabilities")
def list_vulnerabilities(
    request: Request,
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    lang: Literal["en", "pt-br"] = "en",
    q: str | None = Query(None, max_length=100),
    sort: Literal["score", "recent"] = "score",
):
    q = (q or "").strip()
    query = db.query(Vulnerability)
    if q:
        search = f"%{q.replace('%', '').replace('_', '')}%"
        query = query.filter(
            Vulnerability.cve_id.ilike(search)
            | Vulnerability.title.ilike(search)
            | Vulnerability.vendor.ilike(search)
            | Vulnerability.product.ilike(search)
        )

    order = (
        Vulnerability.cisa_date_added.desc().nulls_last()
        if sort == "recent"
        else Vulnerability.custom_risk_score.desc().nulls_last()
    )
    vulns = query.order_by(order).limit(limit).all()

    # CVE não está no banco: busca em tempo real no NVD (com limite por IP).
    cve_candidate = q.upper()
    if not vulns and is_valid_cve_id(cve_candidate):
        search_limiter.check(request)
        res = fetch_new_cve(db, cve_candidate)
        if res.get("status") == "success":
            vulns = [res["vuln"]]

    return [_vuln_to_dict(v, lang) for v in vulns]


@app.get("/api/v1/vulnerabilities/{cve_id}/score")
def explain_score(cve_id: str = CveId, db: Session = Depends(get_db)):
    """Mostra de onde vem a nota de risco (transparência do motor de priorização)."""
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada")
    parts = score_components(ScoreInput(
        cvss_score=vuln.cvss_score, known_exploited=bool(vuln.known_exploited), ransomware_use=vuln.ransomware_use,
        epss_score=vuln.epss_score, cisa_date_added=vuln.cisa_date_added, cisa_due_date=vuln.cisa_due_date,
        published_at=vuln.published_at,
    ))
    return {
        "cve_id": cve_id,
        "score": vuln.custom_risk_score,
        "components": {k: {"value": round(v, 3), "weight": WEIGHTS[k], "points": round(v * WEIGHTS[k] * 10, 2)} for k, v in parts.items()},
    }


@app.get("/api/v1/advisories")
def list_advisories(
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    lang: Literal["en", "pt-br"] = "en",
):
    advisories = db.query(Advisory).order_by(Advisory.published_at.desc().nulls_last()).limit(limit).all()
    result = []
    for a in advisories:
        result.append({
            "id": a.id,
            "title": (a.title_pt or a.title) if lang == "pt-br" else a.title,
            "description": (a.description_pt or a.description) if lang == "pt-br" else a.description,
            "vendor": a.vendor,
            "source_url": a.source_url,
            "published_at": a.published_at,
        })
    return result


def _analysis_payload(vuln: Vulnerability, cached: bool) -> dict:
    try:
        sources = json.loads(vuln.ai_analysis_sources or "[]")
    except ValueError:
        sources = []
    return {
        "cve_id": vuln.cve_id,
        "ai_analysis": vuln.ai_analysis,
        "model": vuln.ai_analysis_model,
        "generated_at": vuln.ai_analysis_at,
        "cached": cached,
        "sources": sources,
    }


@app.get("/api/v1/vulnerabilities/{cve_id}/analysis")
def get_cached_analysis(cve_id: str = CveId, db: Session = Depends(get_db)):
    """Devolve a análise de IA já gerada (não precisa de chave)."""
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not vuln or not vuln.ai_analysis:
        raise HTTPException(status_code=404, detail="Nenhuma análise salva para esta vulnerabilidade.")
    return _analysis_payload(vuln, cached=True)


@app.post("/api/v1/vulnerabilities/{cve_id}/analyze")
def analyze_vulnerability_with_ai(
    request: Request,
    cve_id: str = CveId,
    force: bool = False,
    x_gemini_key: str | None = Header(None, max_length=200),
    db: Session = Depends(get_db),
):
    """Gera (ou reaproveita) a análise da IA usando a chave do próprio usuário."""
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada")

    fresh_until = (vuln.ai_analysis_at or datetime.min) + timedelta(days=config.AI_CACHE_DAYS)
    if vuln.ai_analysis and not force and datetime.utcnow() < fresh_until:
        return _analysis_payload(vuln, cached=True)

    key = (x_gemini_key or "").strip()
    if not key:
        raise HTTPException(status_code=401, detail="CHAVE_API_NAO_FORNECIDA: informe sua chave do Gemini para gerar a análise.")

    ai_limiter.check(request)
    try:
        result = ai.analyze(vuln, key)
    except ai.AIError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    vuln.ai_analysis = result.text
    vuln.ai_analysis_model = result.model
    vuln.ai_analysis_at = datetime.utcnow()
    vuln.ai_analysis_sources = json.dumps(result.sources, ensure_ascii=False)
    db.commit()
    return _analysis_payload(vuln, cached=False)


@app.post("/api/v1/admin/run/{job}", dependencies=[Depends(require_admin)])
def run_job(job: Literal["cisa", "feeds", "epss", "scoring", "nvd", "all"]):
    """Dispara uma coleta manualmente (usado pelo cron do GitHub Actions)."""
    threading.Thread(target=JOBS[job], name=f"admin-{job}", daemon=True).start()
    return {"status": "started", "job": job}
