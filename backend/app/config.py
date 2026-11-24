"""Configuração centralizada lida das variáveis de ambiente."""
import os


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cyberpulse")

# Origens autorizadas a chamar a API pelo navegador (separadas por vírgula).
CORS_ORIGINS = _list("CORS_ORIGINS", "https://cyberpulse-ochre.vercel.app,http://localhost:5173")
# Regex opcional para liberar previews da Vercel, ex: ^https://cyberpulse-[a-z0-9-]+\.vercel\.app$
CORS_ORIGIN_REGEX = os.getenv("CORS_ORIGIN_REGEX") or None

# Token exigido nas rotas administrativas (/api/v1/admin/*). Sem ele, as rotas ficam desligadas.
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# Swagger (/docs) só é exposto se habilitado explicitamente.
ENABLE_DOCS = _bool("ENABLE_DOCS", False)

# Agendador interno (desligar em testes ou quando um cron externo cuidar das coletas).
ENABLE_SCHEDULER = _bool("ENABLE_SCHEDULER", True)

# Chave opcional do NVD: sobe o limite de 5 para 50 requisições a cada 30s.
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip().strip('"')

# Modelos Gemini (configuráveis sem precisar de deploy de código).
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "")
GEMINI_USE_SEARCH = _bool("GEMINI_USE_SEARCH", True)
GEMINI_TIMEOUT_SECONDS = int(os.getenv("GEMINI_TIMEOUT_SECONDS", "90"))
# OpenRouter (reserva, chave do usuário) — SOMENTE modelos gratuitos. Lista em ordem de
# preferência; IDs pagos são ignorados e o roteador "openrouter/free" sempre fecha a lista.
OPENROUTER_MODELS = _list("OPENROUTER_MODELS", "nvidia/nemotron-3-ultra-550b-a55b:free,google/gemma-4-31b-it:free")
OPENROUTER_APP_URL = os.getenv("OPENROUTER_APP_URL", "https://cyberpulse-ochre.vercel.app")

# Por quanto tempo uma análise salva é reaproveitada antes de ser gerada de novo.
AI_CACHE_DAYS = int(os.getenv("AI_CACHE_DAYS", "14"))

# Limites de requisição por IP (por minuto).
RATE_LIMIT_AI_PER_MIN = int(os.getenv("RATE_LIMIT_AI_PER_MIN", "5"))
RATE_LIMIT_SEARCH_PER_MIN = int(os.getenv("RATE_LIMIT_SEARCH_PER_MIN", "10"))
