import httpx
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import Vulnerability

logger = logging.getLogger(__name__)

# URL oficial do catálogo KEV da CISA
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_and_save_cisa_kev(db: Session):
    """
    Busca o JSON oficial da CISA e atualiza/salva no banco de dados.
    """
    logger.info("Iniciando coleta da fonte CISA KEV...")
    
    try:
        # Faz o download do arquivo JSON
        with httpx.Client() as client:
            response = client.get(CISA_KEV_URL, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            
        vulnerabilities = data.get("vulnerabilities", [])
        logger.info(f"[{len(vulnerabilities)}] vulnerabilidades encontradas no JSON da CISA.")
        
        novas = 0
        atualizadas = 0
        
        for item in vulnerabilities:
            cve_id = item.get("cveID")
            
            # Formata as datas que vêm como YYYY-MM-DD
            date_added_str = item.get("dateAdded")
            due_date_str = item.get("dueDate")
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date() if date_added_str else None
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None
            
            # Verifica se já existe no nosso banco pelo CVE
            db_vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
            
            if db_vuln:
                # Atualiza caso já exista
                db_vuln.title = item.get("vulnerabilityName")
                db_vuln.description = item.get("shortDescription")
                db_vuln.vendor = item.get("vendorProject")
                db_vuln.product = item.get("product")
                db_vuln.known_exploited = True
                db_vuln.cisa_date_added = date_added
                db_vuln.cisa_required_action = item.get("requiredAction")
                db_vuln.cisa_due_date = due_date
                atualizadas += 1
            else:
                # Cria uma nova vulnerabilidade
                nova_vuln = Vulnerability(
                    cve_id=cve_id,
                    title=item.get("vulnerabilityName"),
                    description=item.get("shortDescription"),
                    vendor=item.get("vendorProject"),
                    product=item.get("product"),
                    known_exploited=True,
                    cisa_date_added=date_added,
                    cisa_required_action=item.get("requiredAction"),
                    cisa_due_date=due_date,
                    source="CISA KEV"
                )
                db.add(nova_vuln)
                novas += 1
                
        # Salva as alterações no banco de dados (commit)
        db.commit()
        
        logger.info(f"Coleta concluída! {novas} novas adicionadas, {atualizadas} atualizadas.")
        return {"status": "success", "novas": novas, "atualizadas": atualizadas}

    except Exception as e:
        logger.error(f"Erro ao coletar CISA KEV: {str(e)}")
        db.rollback()
        return {"status": "error", "detail": str(e)}
