import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from deep_translator import GoogleTranslator
import google.generativeai as genai

from app.database import engine, Base, SessionLocal, get_db
from app.models import Vulnerability, Advisory
from app.collectors.cisa_kev import fetch_and_save_cisa_kev
from app.collectors.nvd import enrich_cve_with_nvd
from app.collectors.feeds import fetch_and_save_feeds
from app.scoring import calculate_custom_risk_score

logger = logging.getLogger(__name__)
# Backend Inicializado
Base.metadata.create_all(bind=engine)

scheduler = BackgroundScheduler()

def run_nvd_enrichment_job():
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.severity == None).order_by(Vulnerability.cisa_date_added.desc().nulls_last()).first()
        if vuln:
            enrich_cve_with_nvd(db, vuln.cve_id)
    except Exception as e:
        logger.error(f"Erro no job NVD: {e}")
    finally:
        db.close()

def run_feeds_job():
    db = SessionLocal()
    try:
        fetch_and_save_feeds(db)
    except Exception as e:
        logger.error(f"Erro no job Feeds: {e}")
    finally:
        db.close()

def run_translation_job():
    db = SessionLocal()
    try:
        translator = GoogleTranslator(source='auto', target='pt')
        
        # Pega a notícia mais recente não traduzida
        adv = db.query(Advisory).filter(Advisory.title_pt == None).order_by(Advisory.published_at.desc().nulls_last()).first()
        if adv:
            try:
                t = adv.title[:4900] if adv.title else ""
                d = adv.description[:4900] if adv.description else ""
                adv.title_pt = translator.translate(t) if t else adv.title
                adv.description_pt = translator.translate(d) if d else adv.description
                db.commit()
            except:
                db.rollback()
                # Salva o original para não ficar preso no mesmo item
                adv.title_pt = adv.title
                adv.description_pt = adv.description
                db.commit()
            return 
        
        # Pega a vulnerabilidade mais recente não traduzida
        vuln = db.query(Vulnerability).filter(Vulnerability.title_pt == None).order_by(Vulnerability.cisa_date_added.desc().nulls_last()).first()
        if vuln:
            try:
                t = vuln.title[:4900] if vuln.title else ""
                d = vuln.description[:4900] if vuln.description else ""
                act = vuln.cisa_required_action[:4900] if vuln.cisa_required_action else ""
                
                vuln.title_pt = translator.translate(t) if t else vuln.title
                vuln.description_pt = translator.translate(d) if d else vuln.description
                vuln.cisa_required_action_pt = translator.translate(act) if act else vuln.cisa_required_action
                db.commit()
            except:
                db.rollback()
                vuln.title_pt = vuln.title
                vuln.description_pt = vuln.description
                vuln.cisa_required_action_pt = vuln.cisa_required_action
                db.commit()
    except Exception as e:
        pass
    finally:
        db.close()

def run_scoring_job():
    """Fase 4: Calcula o Score Customizado para vulnerabilidades que ainda não tem"""
    db = SessionLocal()
    try:
        vulns = db.query(Vulnerability).filter(Vulnerability.custom_risk_score == None).limit(50).all()
        if vulns:
            for vuln in vulns:
                score = calculate_custom_risk_score(vuln.cvss_score, vuln.known_exploited, vuln.cisa_date_added)
                vuln.custom_risk_score = score
            db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()

scheduler.add_job(run_nvd_enrichment_job, 'interval', seconds=15, id='nvd_job')
scheduler.add_job(run_feeds_job, 'interval', minutes=10, id='feeds_job')
scheduler.add_job(run_translation_job, 'interval', seconds=5, id='translate_job')
scheduler.add_job(run_scoring_job, 'interval', seconds=10, id='scoring_job')

@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.start()
    run_feeds_job()
    run_scoring_job() # Calcula alguns scores no inicio
    yield
    scheduler.shutdown()

app = FastAPI(
    title="CyberPulse API",
    description="API para a Plataforma Aberta de Inteligência em Segurança",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "CyberPulse API está rodando!"}

from app.collectors.nvd import enrich_cve_with_nvd, fetch_new_cve

@app.get("/api/v1/vulnerabilities")
def list_vulnerabilities(db: Session = Depends(get_db), limit: int = 50, lang: str = 'en', q: str = None):
    # Fase 7: Filtro de Busca
    query = db.query(Vulnerability)
    if q:
        search = f"%{q}%"
        query = query.filter(
            (Vulnerability.cve_id.ilike(search)) | 
            (Vulnerability.title.ilike(search)) |
            (Vulnerability.vendor.ilike(search)) |
            (Vulnerability.product.ilike(search))
        )
    
    vulns = query.order_by(Vulnerability.custom_risk_score.desc().nulls_last()).limit(limit).all()
    
    # Fase 8: Se a busca estiver vazia e parecer um CVE (CVE-XXXX-XXXX), buscar no NVD em tempo real
    if q and len(vulns) == 0 and q.upper().startswith("CVE-"):
        logger.info(f"Pesquisa por {q} retornou 0 resultados. Iniciando busca no NVD...")
        res = fetch_new_cve(db, q.upper())
        if res.get("status") == "success":
            # Repete a busca local agora que já foi salvo!
            vulns = query.order_by(Vulnerability.custom_risk_score.desc().nulls_last()).limit(limit).all()
    
    if lang == 'pt-br':
        result = []
        for v in vulns:
            v_dict = v.__dict__.copy()
            v_dict.pop('_sa_instance_state', None)
            if v.title_pt: v_dict['title'] = v.title_pt
            if v.description_pt: v_dict['description'] = v.description_pt
            if v.cisa_required_action_pt: v_dict['cisa_required_action'] = v.cisa_required_action_pt
            result.append(v_dict)
        return result
        
    return vulns

@app.get("/api/v1/advisories")
def list_advisories(db: Session = Depends(get_db), limit: int = 20, lang: str = 'en'):
    advisories = db.query(Advisory).order_by(Advisory.published_at.desc().nulls_last()).limit(limit).all()
    if lang == 'pt-br':
        result = []
        for a in advisories:
            a_dict = a.__dict__.copy()
            a_dict.pop('_sa_instance_state', None)
            if a.title_pt: a_dict['title'] = a.title_pt
            if a.description_pt: a_dict['description'] = a.description_pt
            result.append(a_dict)
        return result
    return advisories

@app.post("/api/v1/vulnerabilities/{cve_id}/analyze")
def analyze_vulnerability_with_ai(cve_id: str, x_gemini_key: str = Header(None), db: Session = Depends(get_db)):
    """Fase 5/9: Integração com IA (Google Gemini) usando Token do Cliente"""
    if not x_gemini_key:
        raise HTTPException(status_code=401, detail="CHAVE_API_NAO_FORNECIDA: Informe sua chave do Gemini para utilizar a IA.")
        
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada")
        
    try:
        # Configura a IA com a chave que o usuário informou no Frontend
        genai.configure(api_key=x_gemini_key)
        model = genai.GenerativeModel('gemini-3.5-flash')
        
        prompt = f"""
        Você é um sistema de Inteligência de Ameaças focado em simplificar problemas complexos de segurança para pessoas leigas.
        Abaixo estão os detalhes de uma vulnerabilidade extraídos do NVD e da CISA:
        
        CVE: {vuln.cve_id}
        Produto/Fabricante: {vuln.vendor} {vuln.product}
        Título: {vuln.title}
        Descrição Técnica Original: {vuln.description}
        Ação Exigida (CISA): {vuln.cisa_required_action}
        
        Sua tarefa é explicar isso de forma extremamente simples, didática e acessível (como se explicasse para um leigo), sem jargões confusos. Forneça:
        
        1. **Contexto do Produto:** O que é o sistema/produto afetado de forma simples?
        2. **A Falha de Segurança:** Explique qual é a falha técnica fazendo analogias simples com o mundo real (ex: porta aberta, chave mestra roubada, etc), para fácil entendimento.
        3. **Plano de Ação:** Traduza a ação da CISA em passos práticos e claros do que deve ser feito.
        
        REGRAS IMPORTANTES: 
        - Responda em Português do Brasil (PT-BR).
        - NÃO adivinhe a profissão do leitor e não use tratamentos (NÃO chame de "analista", "júnior", "amigo", etc).
        - NÃO adicione saudações ou despedidas conversacionais (NÃO diga "olá", nem peça para conversar com você no final). Apenas entregue a explicação formatada.
        """
        
        response = model.generate_content(prompt)
        return {"cve_id": cve_id, "ai_analysis": response.text}
        
    except Exception as e:
        logger.error(f"Erro na IA: {e}")
        raise HTTPException(status_code=500, detail=f"Erro ao conectar com a IA: {str(e)}")

@app.get("/api/v1/collect/cisa")
def trigger_cisa_collection(db: Session = Depends(get_db)):
    return fetch_and_save_cisa_kev(db)

@app.get("/api/v1/collect/nvd/{cve_id}")
def trigger_nvd_enrichment(cve_id: str, db: Session = Depends(get_db)):
    return enrich_cve_with_nvd(db, cve_id)
