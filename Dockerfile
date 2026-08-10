# PII Anonymization Service — BRAI_V2 internal microservice.
# Regex-only mode: no llama.cpp, no BLAS, no CMake. Small and fast.

FROM python:3.11-slim

# Runtime deps only (curl for healthcheck, libpq for psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN mkdir -p /var/log/pii-anonymizer

ENV PII_HOST=0.0.0.0 \
    PII_PORT=8100 \
    PII_USE_LLM=False \
    PII_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8100/health || exit 1

EXPOSE 8100

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
