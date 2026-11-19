import logging
import re
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from app import config
from app.models import Vulnerability
from app.scoring import score_vulnerability

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# Ordem de preferência das métricas CVSS no JSON do NVD.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def is_valid_cve_id(value: str | None) -> bool:
    return bool(value) and bool(CVE_PATTERN.match(value))


def _pick_metric(entries: list[dict]) -> dict:
    # Prefere a nota "Primary" (do próprio NVD) à de terceiros (CNA).
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0]


def extract_cvss(cve_item: dict) -> dict | None:
    """Retorna {score, severity, vector, version} a partir de um item de CVE do NVD."""
    metrics = cve_item.get("metrics", {}) or {}
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = _pick_metric(entries)
        data = metric.get("cvssData", {}) or {}
        score = data.get("baseScore")
        if score is None:
            continue
        # No CVSS v2 a severidade fica fora de cvssData.
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        return {
            "score": str(score),
            "severity": (severity or "UNKNOWN").upper(),
            "vector": data.get("vectorString"),
            "version": data.get("version"),
        }
    return None


def extract_vendor_product(cve_item: dict) -> tuple[str | None, str | None]:
    """Extrai fabricante/produto do primeiro CPE vulnerável (cpe:2.3:a:vendor:product:...)."""
    for conf in cve_item.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4:
                    return parts[3].replace("_", " "), parts[4].replace("_", " ")
    return None, None


def _published(cve_item: dict):
    raw = cve_item.get("published")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _fetch_nvd(cve_id: str) -> dict | None:
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    with httpx.Client(timeout=30.0, headers=headers) as client:
        response = client.get(NVD_BASE_URL, params={"cveId": cve_id})
        response.raise_for_status()
        items = response.json().get("vulnerabilities", [])
    return items[0].get("cve", {}) if items else None


def enrich_cve_with_nvd(db: Session, cve_id: str):
    """Busca CVSS/data de publicação no NVD para um CVE que já está no banco."""
    db_vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not db_vuln:
        return {"status": "error", "message": f"{cve_id} não existe no banco."}

    try:
        cve_item = _fetch_nvd(cve_id)
    except httpx.HTTPStatusError as e:
        logger.warning("NVD respondeu %s para %s", e.response.status_code, cve_id)
        # 403/429/5xx = limite ou instabilidade: não marca como verificado, tenta depois.
        return {"status": "error", "detail": f"NVD HTTP {e.response.status_code}"}
    except httpx.HTTPError as e:
        logger.warning("Falha de rede no NVD para %s: %s", cve_id, type(e).__name__)
        return {"status": "error", "detail": "falha de rede"}

    # Marca como verificado mesmo sem CVSS, para o job não ficar preso no mesmo CVE.
    db_vuln.nvd_checked_at = datetime.utcnow()
    result = {"status": "warning", "message": "NVD ainda não publicou nota CVSS."}
    if cve_item:
        db_vuln.published_at = db_vuln.published_at or _published(cve_item)
        cvss = extract_cvss(cve_item)
        if cvss:
            db_vuln.severity = cvss["severity"]
            db_vuln.cvss_score = cvss["score"]
            db_vuln.cvss_vector = cvss["vector"]
            result = {"status": "success", "cve_id": cve_id, "severity": cvss["severity"], "cvss_score": cvss["score"]}
    db_vuln.custom_risk_score = score_vulnerability(db_vuln)
    db_vuln.score_updated_at = datetime.utcnow()
    db.commit()
    logger.info("NVD %s: %s", cve_id, result["status"])
    return result


def fetch_new_cve(db: Session, cve_id: str):
    """Busca um CVE que ainda não está no banco e o salva."""
    if not is_valid_cve_id(cve_id):
        return {"status": "error", "message": "Formato de CVE inválido."}
    try:
        cve_item = _fetch_nvd(cve_id)
    except httpx.HTTPError as e:
        logger.warning("Falha ao buscar %s no NVD: %s", cve_id, type(e).__name__)
        return {"status": "error", "message": "NVD indisponível no momento."}

    if not cve_item:
        return {"status": "error", "message": f"{cve_id} não encontrado no NVD."}

    descriptions = cve_item.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "Sem descrição")
    title = desc_en.split(". ")[0][:250] if desc_en else cve_id
    cvss = extract_cvss(cve_item) or {}
    vendor, product = extract_vendor_product(cve_item)

    nova_vuln = Vulnerability(
        cve_id=cve_id,
        title=title,
        description=desc_en,
        vendor=vendor or "Desconhecido",
        product=product or "Desconhecido",
        severity=cvss.get("severity", "UNKNOWN"),
        cvss_score=cvss.get("score"),
        cvss_vector=cvss.get("vector"),
        published_at=_published(cve_item),
        known_exploited=False,  # só a CISA define isso
        nvd_checked_at=datetime.utcnow(),
        source="NVD API Realtime",
    )
    nova_vuln.custom_risk_score = score_vulnerability(nova_vuln)
    nova_vuln.score_updated_at = datetime.utcnow()
    db.add(nova_vuln)
    db.commit()
    logger.info("%s adicionado via NVD.", cve_id)
    return {"status": "success", "vuln": nova_vuln}
