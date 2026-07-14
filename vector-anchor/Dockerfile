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
ENV MONOLITH_CHROMA_PATH=/app/chroma_store \
    MONOLITH_EMBEDDING=hash
EXPOSE 8001
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8001"]
