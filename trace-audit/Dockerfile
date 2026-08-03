# TraceAudit (Python/FastAPI streaming) — reasoning-layer defense.
# Uses the offline "mock" model backend by default (no model download); set
# MONOLITH_MODEL_BACKEND=ollama + MONOLITH_OLLAMA_URL to use a real one.

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY fixtures ./fixtures
RUN useradd --system --uid 10001 --create-home monolith \
    && mkdir -p /var/lib/monolith \
    && chown -R monolith:monolith /app /var/lib/monolith
ENV MONOLITH_BASELINE_PATH=/app/baseline_distribution.json \
    MONOLITH_MODEL_BACKEND=mock
EXPOSE 8002
# Capture the baseline distribution at startup, then serve.
USER monolith
CMD ["sh", "-c", "python fixtures/baseline_capture.py && uvicorn src.main:app --host 0.0.0.0 --port 8002"]
