# VectorAnchor (Python/FastAPI) — memory-layer defense.
# ChromaDB runs embedded, so there is no separate vector-DB service.

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
    && mkdir -p /var/lib/monolith /app/chroma_store \
    && chown -R monolith:monolith /app /var/lib/monolith
ENV MONOLITH_CHROMA_PATH=/app/chroma_store \
    MONOLITH_EMBEDDING=hash
EXPOSE 8001
USER monolith
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8001"]
