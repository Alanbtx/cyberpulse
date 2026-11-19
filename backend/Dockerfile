FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Não roda como root
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# Sem --reload em produção. --proxy-headers faz o uvicorn usar o IP real (X-Forwarded-For)
# vindo do proxy do Render, necessário para o limite de requisições por IP.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
