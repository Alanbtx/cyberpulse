from sqlalchemy import Column, Integer, String, Text, Boolean, Date, DateTime, Float
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
    
    # Informações do Fabricante/Produto
    vendor = Column(String, nullable=True)
    product = Column(String, nullable=True)
    
    # Flags importantes
    known_exploited = Column(Boolean, default=False)
    
    # Informações CISA específicas
    cisa_date_added = Column(Date, nullable=True)
    cisa_required_action = Column(Text, nullable=True)
    cisa_required_action_pt = Column(Text, nullable=True)
    cisa_due_date = Column(Date, nullable=True)
    
    # Nossa Inteligência
    custom_risk_score = Column(Float, nullable=True)

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
