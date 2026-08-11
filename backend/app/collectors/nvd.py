import httpx
import logging
import time
from sqlalchemy.orm import Session
from app.models import Vulnerability

logger = logging.getLogger(__name__)

# O NVD limita requisições sem API Key. Precisamos ser cuidadosos.
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def enrich_cve_with_nvd(db: Session, cve_id: str):
    """
    Busca detalhes técnicos (CVSS, severidade) no NVD para um CVE específico.
    """
    logger.info(f"Buscando informações no NVD para {cve_id}...")
    
    # 1. Verifica se a vulnerabilidade existe no nosso banco primeiro
    db_vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    
    if not db_vuln:
        return {"status": "error", "message": f"A vulnerabilidade {cve_id} não existe no nosso banco de dados. Adicione ela primeiro!"}

    try:
        # 2. Faz a chamada na API oficial do governo (NVD)
        # O parâmetro cveId garante que buscaremos apenas ela
        with httpx.Client() as client:
            response = client.get(
                NVD_BASE_URL, 
                params={"cveId": cve_id}, 
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
            
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return {"status": "warning", "message": "Nenhuma informação extra encontrada no NVD."}
            
        # 3. Extrai as métricas de dentro do JSON complexo do NVD
        cve_item = vulnerabilities[0].get("cve", {})
        metrics = cve_item.get("metrics", {})
        
        # Tenta achar o CVSS na versão 3.1, ou 3.0, ou 2.0
        cvss_data = None
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            
        if cvss_data:
            # 4. Salva a severidade, o score CVSS e o vetor no banco
            db_vuln.severity = cvss_data.get("baseSeverity")
            db_vuln.cvss_score = str(cvss_data.get("baseScore"))
            db_vuln.cvss_vector = cvss_data.get("vectorString")
            
            db.commit()
            logger.info(f"Sucesso! {cve_id} atualizado: Severidade {db_vuln.severity}, Score {db_vuln.cvss_score}")
            return {
                "status": "success", 
                "cve_id": cve_id, 
                "severity": db_vuln.severity,
                "cvss_score": db_vuln.cvss_score
            }
        else:
            return {"status": "warning", "message": "NVD não retornou nota CVSS para este item."}

    except Exception as e:
        logger.error(f"Erro ao buscar no NVD: {str(e)}")
        return {"status": "error", "detail": str(e)}

def fetch_new_cve(db: Session, cve_id: str):
    """
    Fase 8: Busca um CVE totalmente novo na API do NVD e o salva no banco.
    """
    logger.info(f"CVE não encontrado no banco. Tentando buscar {cve_id} diretamente do NVD...")
    
    try:
        with httpx.Client() as client:
            response = client.get(
                NVD_BASE_URL, 
                params={"cveId": cve_id}, 
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
            
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return {"status": "error", "message": f"CVE {cve_id} não encontrado na base global do NVD."}
            
        cve_item = vulnerabilities[0].get("cve", {})
        
        # Extrai Descrição e Título
        descriptions = cve_item.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d["lang"] == "en"), "Sem descrição")
        
        # NVD não tem "Título", usaremos a descrição cortada ou o próprio ID
        title = desc_en.split(".")[0] if desc_en else cve_id
        
        # Extrai CVSS
        metrics = cve_item.get("metrics", {})
        cvss_data = None
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            
        severity = cvss_data.get("baseSeverity") if cvss_data else "UNKNOWN"
        cvss_score = str(cvss_data.get("baseScore")) if cvss_data else None
        cvss_vector = cvss_data.get("vectorString") if cvss_data else None
        
        # Identifica Vendor/Product via CPE se possível (complexo no JSON v2 do NVD, usaremos "NVD" como fallback)
        nova_vuln = Vulnerability(
            cve_id=cve_id,
            title=title,
            description=desc_en,
            vendor="Desconhecido (Buscado via NVD)",
            product="Desconhecido",
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            known_exploited=False, # Só CISA define isso
            source="NVD API Realtime"
        )
        db.add(nova_vuln)
        db.commit()
        
        from app.scoring import calculate_custom_risk_score
        nova_vuln.custom_risk_score = calculate_custom_risk_score(cvss_score, False, None)
        db.commit()
        
        logger.info(f"Sucesso! {cve_id} adicionado ao banco.")
        return {"status": "success", "vuln": nova_vuln}

    except Exception as e:
        logger.error(f"Erro ao buscar novo CVE no NVD: {str(e)}")
        return {"status": "error", "detail": str(e)}
