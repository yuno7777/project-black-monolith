"""VectorAnchor FastAPI service — memory-layer defense for Project Black
Monolith.

Wraps a ChromaDB retriever and quarantines corpus-poisoning "universal bait"
documents before they reach an agent's context window. Demo/fixture scripts
drive it through POST /retrieve.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from secrets import compare_digest

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .config import MODULE_NAME, load_config
from .detector_state import DetectorStateStore
from .events import context_from_headers, make_emitter, replay_dead_letters
from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine
from .retriever_proxy import RetrieverProxy
from .store import build_embedding_function, get_or_create_collection

MAX_QUERY_LENGTH = 16_384
MAX_QUERY_BYTES = 16_384
MAX_DOCUMENT_TEXT_BYTES = 64 * 1024
MAX_DOCUMENT_BATCH_BYTES = 1024 * 1024


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetrieveRequest(StrictRequest):
    query: str = Field(max_length=MAX_QUERY_LENGTH)
    k: int | None = Field(default=None, ge=1, le=100)

    @field_validator("query")
    @classmethod
    def query_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("query must not be blank")
        if len(value.encode("utf-8")) > MAX_QUERY_BYTES:
            raise ValueError(f"query must be at most {MAX_QUERY_BYTES} UTF-8 bytes")
        return value


class SeedDemoRequest(StrictRequest):
    """Ask for the local detection-fixture corpus to be loaded."""

    include_bait: bool = False


class Document(StrictRequest):
    id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def id_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("document id must not be blank")
        if any(not character.isprintable() for character in value):
            raise ValueError("document id must contain only printable characters")
        return value

    @field_validator("text")
    @classmethod
    def text_must_be_bounded(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("document text must not be blank")
        if len(value.encode("utf-8")) > MAX_DOCUMENT_TEXT_BYTES:
            raise ValueError(
                f"document text must be at most {MAX_DOCUMENT_TEXT_BYTES} UTF-8 bytes"
            )
        return value


class AddDocumentsRequest(StrictRequest):
    documents: list[Document] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_batch(self):
        ids = [document.id for document in self.documents]
        if len(set(ids)) != len(ids):
            raise ValueError("document ids must be unique within a batch")
        total_bytes = sum(len(document.text.encode("utf-8")) for document in self.documents)
        if total_bytes > MAX_DOCUMENT_BATCH_BYTES:
            raise ValueError(
                f"document batch must be at most {MAX_DOCUMENT_BATCH_BYTES} UTF-8 bytes"
            )
        return self


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
        allow_insecure_http=cfg.allow_insecure_dashboard,
    )
    embed_fn = build_embedding_function(cfg)
    collection = get_or_create_collection(cfg, embedding_function=embed_fn)
    state_store = DetectorStateStore(
        cfg.detector_state_path,
        min_distinct_topics=cfg.min_distinct_topics,
        topic_similarity=cfg.topic_similarity,
        retention_horizon=cfg.retention_horizon,
        max_queries_per_doc=cfg.max_queries_per_doc,
        max_tracked_docs=cfg.max_tracked_docs,
    )
    try:
        restored = state_store.load()
    except ValueError as error:
        # State written under different retention policy or an older schema.
        # Refusing to reinterpret it is deliberate — scores under mixed rules
        # would be unreproducible — but crash-looping the service is not a
        # safe alternative either, so set the old file aside (never delete
        # evidence) and continue from empty detector state.
        quarantined = state_store.quarantine_unreadable()
        logging.error(
            "detector state could not be loaded (%s); moved to %s and started "
            "with empty detection state",
            error,
            quarantined,
        )
        restored = None
    if restored:
        tracker, quarantine = restored
    else:
        tracker = FrequencyTracker(
            min_distinct_topics=cfg.min_distinct_topics,
            topic_similarity=cfg.topic_similarity,
            retention_horizon=cfg.retention_horizon,
            max_queries_per_doc=cfg.max_queries_per_doc,
            max_tracked_docs=cfg.max_tracked_docs,
        )
        quarantine = Quarantine()
    return RetrieverProxy(
        collection=collection,
        embed_fn=embed_fn,
        tracker=tracker,
        quarantine=quarantine,
        cfg=cfg,
        emit=emit,
        state_store=state_store,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.proxy = build_proxy()
    emit = app.state.proxy.emit
    emit(
        "service_start",
        "info",
        {"message": "VectorAnchor memory-layer defense online"},
    )
    try:
        yield
    finally:
        app.state.proxy.flush_state()
        emit("service_stop", "info", {"message": "VectorAnchor shutting down"})
        emit.close()


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


def _require_admin_token(request: Request) -> None:
    _require_admin(request)


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
    _require_admin_token(request)
    proxy: RetrieverProxy = app.state.proxy
    total = proxy.upsert_documents([(document.id, document.text) for document in req.documents])
    return {"added": len(req.documents), "total": total}


def _demo_corpus() -> tuple[list[tuple[str, str]], str, str]:
    """Load the demo corpus fixture.

    The corpus lives with the other fixtures so that exactly one copy of it
    exists in the repository, and the dashboard can seed the corpus without
    holding a second copy. It is imported lazily and defensively: the
    service has to start even where the fixtures were not shipped, and only
    this endpoint needs them.
    """
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    if str(fixtures) not in sys.path:
        sys.path.insert(0, str(fixtures))
    try:
        from corpus_data import CLEAN_DOCS, POISON_DOC_ID, POISON_DOC_TEXT
    except ImportError as error:
        raise HTTPException(
            status_code=503, detail="the demo corpus fixture is not available"
        ) from error
    return [(doc_id, text) for doc_id, text in CLEAN_DOCS], POISON_DOC_ID, POISON_DOC_TEXT


@app.post("/admin/seed-demo")
def seed_demo(req: SeedDemoRequest, request: Request) -> dict:
    """Load the local demo corpus into the collection.

    Every document here is a synthetic detection fixture — benign text across
    twelve unrelated topics, plus optionally one "universal bait" document
    that exists so the memory layer's quarantine can be demonstrated. This
    endpoint is what the dashboard's onboarding page calls so that an
    operator does not have to run the seed fixture by hand.

    Seeding is idempotent: documents are upserted by id, so pressing the
    button twice leaves the corpus in the same state.
    """
    _require_admin_token(request)
    clean, bait_id, bait_text = _demo_corpus()
    documents = clean + ([(bait_id, bait_text)] if req.include_bait else [])
    proxy: RetrieverProxy = app.state.proxy
    total = proxy.upsert_documents(documents)
    return {
        "added": len(documents),
        "total": total,
        "bait": bool(req.include_bait),
    }


@app.get("/quarantine")
def quarantine(request: Request) -> dict:
    _require_admin_token(request)
    proxy: RetrieverProxy = app.state.proxy
    documents = proxy.quarantine_snapshot()
    return {
        "count": len(documents),
        "documents": [
            {
                "doc_id": d.doc_id,
                "reason": d.reason,
                "score": d.score,
                "preview": d.preview,
                "quarantined_at_ms": d.quarantined_at_ms,
            }
            for d in documents
        ],
    }


@app.delete("/quarantine/{doc_id}")
def delete_quarantined_document(doc_id: str, request: Request) -> dict:
    _require_admin_token(request)
    cleaned = doc_id.strip()
    if (
        not cleaned
        or len(cleaned) > 128
        or any(not character.isprintable() for character in cleaned)
    ):
        raise HTTPException(status_code=422, detail="invalid document id")
    proxy: RetrieverProxy = app.state.proxy
    if hasattr(proxy, "release_quarantine"):
        return proxy.release_quarantine(cleaned)
    released = cleaned in proxy.quarantine.list_ids()
    proxy.quarantine.remove_many([cleaned])
    proxy.tracker.reset_doc(cleaned)
    if hasattr(proxy, "flush_state"):
        proxy.flush_state()
    return {
        "doc_id": cleaned,
        "released": released,
        "quarantined_count": len(proxy.quarantine.list_ids()),
    }


@app.get("/stats")
def stats(request: Request) -> dict:
    _require_admin_token(request)
    proxy: RetrieverProxy = app.state.proxy
    return {
        "module": MODULE_NAME,
        "documents": proxy.collection.count(),
        "quarantined": proxy.quarantine_size(),
        "delivery": proxy.emit.delivery_stats(),
        "config": {
            "top_k": proxy.cfg.top_k,
            "min_distinct_topics": proxy.cfg.min_distinct_topics,
            "topic_similarity": proxy.cfg.topic_similarity,
            "retention_horizon": proxy.cfg.retention_horizon,
            "max_queries_per_doc": proxy.cfg.max_queries_per_doc,
        },
    }


@app.post("/admin/reset-detection")
def reset_detection(request: Request) -> dict:
    """Clear the tracker + quarantine (not the corpus). Lets the demo script
    re-run detection from a clean slate without re-seeding."""
    _require_admin_token(request)
    proxy: RetrieverProxy = app.state.proxy
    proxy.reset_detection()
    return {"status": "reset"}


@app.post("/admin/replay-dead-letters")
def admin_replay_dead_letters(request: Request) -> dict:
    """Reset dead-lettered outbox events back to pending for immediate retry."""
    _require_admin_token(request)
    proxy: RetrieverProxy = app.state.proxy
    target = (
        getattr(getattr(proxy, "emit", None), "outbox", None)
        or getattr(proxy, "outbox", None)
        or getattr(proxy, "emit", None)
    )
    return {"replayed": replay_dead_letters(target)}
