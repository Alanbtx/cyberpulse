from sqlalchemy import Boolean, Column, Date, DateTime, Float, Integer, String, Text
from sqlalchemy.sql import func

from .database import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    title_pt = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    description_pt = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(String, nullable=True)
    cvss_vector = Column(String, nullable=True)
    published_at = Column(Date, nullable=True)

    # Informações do Fabricante/Produto
    vendor = Column(String, nullable=True)
    product = Column(String, nullable=True)

    # Sinais de exploração
    known_exploited = Column(Boolean, default=False)
    ransomware_use = Column(Boolean, nullable=True)
    epss_score = Column(Float, nullable=True)        # probabilidade (0-1) de exploração em 30 dias
    epss_percentile = Column(Float, nullable=True)
    epss_updated_at = Column(DateTime, nullable=True)

    # Informações CISA específicas
    cisa_date_added = Column(Date, nullable=True)
    cisa_required_action = Column(Text, nullable=True)
    cisa_required_action_pt = Column(Text, nullable=True)
    cisa_due_date = Column(Date, nullable=True)

    # Nossa Inteligência
    custom_risk_score = Column(Float, nullable=True)
    score_updated_at = Column(DateTime, nullable=True)
    nvd_checked_at = Column(DateTime, nullable=True)

    # Cache da análise de IA (é igual para todos os usuários, então reaproveitamos)
    ai_analysis = Column(Text, nullable=True)
    ai_analysis_model = Column(String, nullable=True)
    ai_analysis_at = Column(DateTime, nullable=True)
    ai_analysis_sources = Column(Text, nullable=True)  # JSON [{title, url}]

    # Metadados do sistema
    source = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Advisory(Base):
    __tablename__ = "advisories"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    title_pt = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    description_pt = Column(Text, nullable=True)
    source_url = Column(String, unique=True, index=True, nullable=False)
    published_at = Column(DateTime, nullable=True)

    # Metadados do sistema
    created_at = Column(DateTime(timezone=True), server_default=func.now())
