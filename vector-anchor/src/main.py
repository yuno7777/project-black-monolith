"""VectorAnchor FastAPI service — memory-layer defense for Project Black
Monolith.

Wraps a ChromaDB retriever and quarantines corpus-poisoning "universal bait"
documents before they reach an agent's context window. Demo/fixture scripts
drive it through POST /retrieve.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from secrets import compare_digest

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from .config import MODULE_NAME, load_config
from .events import context_from_headers, make_emitter
from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine
from .retriever_proxy import RetrieverProxy
from .store import build_embedding_function, get_or_create_collection


class RetrieveRequest(BaseModel):
    query: str
    k: int | None = None


class Document(BaseModel):
    id: str
    text: str


class AddDocumentsRequest(BaseModel):
    documents: list[Document]


def build_proxy() -> RetrieverProxy:
    cfg = load_config()
    emit = make_emitter(
        MODULE_NAME,
        cfg.dashboard_url,
        cfg.event_token,
        cfg.event_outbox_path,
        tenant_id=cfg.tenant_id,
        agent_id=cfg.agent_id,
        session_id=cfg.session_id,
    )
    embed_fn = build_embedding_function(cfg)
    collection = get_or_create_collection(cfg, embedding_function=embed_fn)
    tracker = FrequencyTracker(
        min_distinct_topics=cfg.min_distinct_topics,
        topic_similarity=cfg.topic_similarity,
        window_size=cfg.window_size,
    )
    quarantine = Quarantine()
    return RetrieverProxy(
        collection=collection,
        embed_fn=embed_fn,
        tracker=tracker,
        quarantine=quarantine,
        cfg=cfg,
        emit=emit,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.proxy = build_proxy()
    app.state.proxy.emit(
        "service_start",
        "info",
        {"message": "VectorAnchor memory-layer defense online"},
    )
    yield


app = FastAPI(title="Project Black Monolith — VectorAnchor", lifespan=lifespan)


def _admin_credential_valid(expected: str | None, authorization: str) -> bool:
    if not expected or len(expected) < 16 or not authorization.startswith("Bearer "):
        return False
    supplied = authorization[len("Bearer ") :]
    return bool(supplied) and compare_digest(supplied, expected)


def _require_admin(request: Request) -> None:
    """Authenticate corpus and detector-state mutations."""
    proxy: RetrieverProxy = app.state.proxy
    expected = proxy.cfg.admin_token
    if not expected or len(expected) < 16:
        raise HTTPException(
            status_code=503,
            detail="administrative authentication is unavailable",
        )
    if not _admin_credential_valid(expected, request.headers.get("authorization", "")):
        raise HTTPException(status_code=401, detail="invalid administrative credential")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "module": MODULE_NAME,
    }


@app.post("/retrieve")
def retrieve(req: RetrieveRequest, request: Request) -> dict:
    # The caller (an agent framework) propagates its identity in X-Monolith-*
    # headers; anything it does not send falls back to this process's
    # configured defaults inside the emitter.
    proxy: RetrieverProxy = app.state.proxy
    return proxy.retrieve(req.query, req.k, context_from_headers(request.headers))


@app.post("/admin/add-documents")
def add_documents(req: AddDocumentsRequest, request: Request) -> dict:
    """Insert (or upsert) documents into the corpus. The service owns the
    single ChromaDB client, so the seed/inject fixtures route all corpus
    mutations through here rather than opening a second client (which would
    contend on ChromaDB's SQLite store)."""
    _require_admin(request)
    proxy: RetrieverProxy = app.state.proxy
    proxy.collection.upsert(
        ids=[d.id for d in req.documents],
        documents=[d.text for d in req.documents],
    )
    return {"added": len(req.documents), "total": proxy.collection.count()}


@app.get("/quarantine")
def quarantine(request: Request) -> dict:
    _require_admin(request)
    proxy: RetrieverProxy = app.state.proxy
    return {
        "count": len(proxy.quarantine),
        "documents": [
            {
                "doc_id": d.doc_id,
                "reason": d.reason,
                "score": d.score,
                "preview": d.preview,
                "quarantined_at_ms": d.quarantined_at_ms,
            }
            for d in proxy.quarantine.all()
        ],
    }


@app.get("/stats")
def stats(request: Request) -> dict:
    _require_admin(request)
    proxy: RetrieverProxy = app.state.proxy
    return {
        "module": MODULE_NAME,
        "documents": proxy.collection.count(),
        "quarantined": len(proxy.quarantine),
        "config": {
            "top_k": proxy.cfg.top_k,
            "min_distinct_topics": proxy.cfg.min_distinct_topics,
            "topic_similarity": proxy.cfg.topic_similarity,
            "window_size": proxy.cfg.window_size,
        },
    }


@app.post("/admin/reset-detection")
def reset_detection(request: Request) -> dict:
    """Clear the tracker + quarantine (not the corpus). Lets the demo script
    re-run detection from a clean slate without re-seeding."""
    _require_admin(request)
    proxy: RetrieverProxy = app.state.proxy
    proxy.tracker = FrequencyTracker(
        min_distinct_topics=proxy.cfg.min_distinct_topics,
        topic_similarity=proxy.cfg.topic_similarity,
        window_size=proxy.cfg.window_size,
    )
    proxy.quarantine = Quarantine()
    return {"status": "reset"}
