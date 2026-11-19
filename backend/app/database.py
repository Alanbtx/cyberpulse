import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DATABASE_URL

logger = logging.getLogger(__name__)

# Render/Heroku às vezes entregam "postgres://", que o SQLAlchemy 2 não aceita.
_url = DATABASE_URL.replace("postgres://", "postgresql://", 1) if DATABASE_URL.startswith("postgres://") else DATABASE_URL

_engine_kwargs = {"pool_pre_ping": True}
if _url.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(_url, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Colunas adicionadas depois da primeira versão. `create_all` não altera tabelas
# existentes, então adicionamos o que faltar aqui (migração leve e idempotente).
_NEW_COLUMNS = {
    "vulnerabilities": {
        "published_at": "DATE",
        "epss_score": "FLOAT",
        "epss_percentile": "FLOAT",
        "epss_updated_at": "TIMESTAMP",
        "ransomware_use": "BOOLEAN",
        "nvd_checked_at": "TIMESTAMP",
        "score_updated_at": "TIMESTAMP",
        "ai_analysis": "TEXT",
        "ai_analysis_model": "VARCHAR",
        "ai_analysis_at": "TIMESTAMP",
        "ai_analysis_sources": "TEXT",
    }
}


def run_migrations():
    Base.metadata.create_all(bind=engine)
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, columns in _NEW_COLUMNS.items():
            existing = {c["name"] for c in insp.get_columns(table)}
            for name, ddl_type in columns.items():
                if name not in existing:
                    logger.info("Migração: adicionando %s.%s", table, name)
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type}"))
