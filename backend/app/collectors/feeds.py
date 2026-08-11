import feedparser
import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
from sqlalchemy.orm import Session
from app.models import Advisory

logger = logging.getLogger(__name__)

FEEDS = [
    {"vendor": "CISA", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    # Podemos adicionar outros depois (ex: Microsoft, Red Hat, etc)
]

def fetch_and_save_feeds(db: Session):
    """
    Busca notícias/advisories recentes de fontes RSS oficiais e salva no banco.
    """
    logger.info("Iniciando coleta de Feeds RSS...")
    novos = 0

    for feed_info in FEEDS:
        vendor = feed_info["vendor"]
        url = feed_info["url"]
        
        try:
            parsed = feedparser.parse(url)
            
            # Pegamos os 15 mais recentes de cada feed para ser rápido
            for entry in parsed.entries[:15]:
                # Evita duplicados pela URL
                source_url = entry.link
                db_adv = db.query(Advisory).filter(Advisory.source_url == source_url).first()
                
                if not db_adv:
                    # Converte a data do RSS (RFC 822) para datetime
                    pub_date = None
                    if hasattr(entry, 'published'):
                        try:
                            pub_date = parsedate_to_datetime(entry.published).replace(tzinfo=None)
                        except Exception:
                            pass
                    
                    novo_adv = Advisory(
                        title=entry.title,
                        vendor=vendor,
                        description=entry.summary if hasattr(entry, 'summary') else "",
                        source_url=source_url,
                        published_at=pub_date
                    )
                    db.add(novo_adv)
                    novos += 1
            
            db.commit()
        except Exception as e:
            logger.error(f"Erro ao processar o feed {vendor}: {str(e)}")
            db.rollback()

    logger.info(f"Coleta de Feeds concluída. {novos} notícias/alertas novos.")
    return {"status": "success", "novas_noticias": novos}
