import os
import sys
from pathlib import Path

# Banco SQLite temporário e sem agendador/coletas reais durante os testes.
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(__file__).parent / "test.db")
os.environ["ENABLE_SCHEDULER"] = "false"
os.environ["ADMIN_TOKEN"] = "test-admin-token"
os.environ["CORS_ORIGINS"] = "https://cyberpulse-ochre.vercel.app"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
