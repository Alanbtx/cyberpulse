import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Lê a URL do banco de dados das variáveis de ambiente (o padrão é local)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cyberpulse")

# Cria a engine de conexão com o banco
engine = create_engine(DATABASE_URL)

# Cria o gerenciador de sessões para conversarmos com o banco
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Classe base que usaremos para criar nossas tabelas
Base = declarative_base()

# Função auxiliar para garantir que a sessão feche após o uso na nossa API
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
