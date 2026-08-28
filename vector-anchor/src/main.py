"""VectorAnchor FastAPI service — memory-layer defense for Project Black
Monolith.

WHAT THIS FILE IS
-----------------
The web server / entry point of the VectorAnchor module. It is the only place
in this module that talks HTTP to the outside world. It:

  1. Builds the whole detection pipeline once at startup (build_proxy()).
  2. Exposes the endpoints an agent's retrieval framework calls:
       POST /retrieve          — the main one: a proxied vector search with
                                 poisoning quarantine
       POST /admin/add-documents — used by the seed/inject fixtures
       GET  /quarantine        — admin: inspect what got quarantined
       GET  /stats             — admin: health/delivery/config, read by the
                                 dashboard Operations page
       POST /admin/reset-detection — admin: clear detector memory (demo)
       GET  /health            — Docker healthcheck target
  3. Guards the admin endpoints with a separate MONOLITH_ADMIN_TOKEN so that
     corpus mutations (which can change what the detector sees) are not
     available to whoever can reach /retrieve.

WHO CALLS WHAT (the flow this file anchors)
------------------------------------------
  Agent runtime
    -> POST /retrieve {query, k?} + X-Monolith-* headers   (this file)
    -> RetrieverProxy.retrieve()        (retriever_proxy.py)
    -> FrequencyTracker + Quarantine    (frequency_tracker.py, quarantine.py)
    -> event emitted via EventEmitter   (events.py)
    -> outbox -> dashboard POST /api/ingest (dashboard/app/api/ingest/route.ts)

  run_full_demo.sh (via docker compose exec)
    -> fixtures/seed_corpus.py & inject_poison.py
    -> POST /admin/add-documents        (this file)
    -> RetrieverProxy.upsert_documents() (retriever_proxy.py)

  dashboard/app/api/operations/route.ts
    -> GET /stats with MONOLITH_MODULE_ADMIN_TOKEN  (this file)
    -> shows outbox delivery backlog/dead letters on the Operations page
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from secrets import compare_digest

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Module-internal imports. Each one is a piece of the detection pipeline:
from .config import MODULE_NAME, load_config          # env -> validated Config
from .detector_state import DetectorStateStore        # atomic JSON persistence
from .events import context_from_headers, make_emitter  # event delivery (shared
                                                       # outbox, see python-common/)
from .frequency_tracker import FrequencyTracker        # the poison detector itself
from .quarantine import Quarantine                     # holds quarantined docs
from .retriever_proxy import RetrieverProxy            # the /retrieve choke point
from .store import build_embedding_function, get_or_create_collection  # ChromaDB

# Input bounds. Everything entering via HTTP is treated as untrusted.
MAX_QUERY_LENGTH = 16_384            # bytes of query text (requests are capped)
MAX_DOCUMENT_TEXT_BYTES = 64 * 1024  # per document
MAX_DOCUMENT_BATCH_BYTES = 1024 * 1024  # per batch


class StrictRequest(BaseModel):
    # Pydantic: reject any field the API does not declare. A typo'd or hostile
    # extra field becomes a 422 instead of being silently ignored.
    model_config = ConfigDict(extra="forbid")


class RetrieveRequest(StrictRequest):
    """The body of POST /retrieve. Public input is deliberately named `k` (not
    `n_results`) so ChromaDB's internal parameter name never leaks into the
    API contract — contracts/check_contracts.py pins this."""

    query: str = Field(max_length=MAX_QUERY_LENGTH)
    k: int | None = Field(default=None, ge=1, le=100)  # how many results wanted

    @field_validator("query")
    @classmethod
    def query_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("query must not be blank")
        return value


class Document(StrictRequest):
    """One corpus document for /admin/add-documents."""

    id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def id_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("document id must not be blank")
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
    """Body of POST /admin/add-documents: 1-100 documents, unique ids, bounded
    total size. Validation happens in Pydantic so bad batches 422 before any
    ChromaDB work."""

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
    """Assemble the whole detection pipeline. Called ONCE, from lifespan().

    Order matters:
      1. load_config()               -> validated settings (config.py)
      2. make_emitter(...)           -> event delivery object (events.py); the
                                       outbox thread starts immediately
      3. build_embedding_function()  -> hash embedder or sentence-transformers
                                       (store.py)
      4. get_or_create_collection()  -> the ONE ChromaDB PersistentClient +
                                       collection (store.py)
      5. DetectorStateStore(...)     -> loads detector_state.json if present
      6. If the saved state is unreadable (policy changed / old schema):
         move it aside as "<name>.unreadable" — never delete evidence — and
         start with an empty FrequencyTracker + Quarantine.
      7. Wrap everything in a RetrieverProxy and return it.

    The returned proxy is stored on app.state.proxy and used by every route.
    """
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
    state_store = DetectorStateStore(
        cfg.detector_state_path,
        min_distinct_topics=cfg.min_distinct_topics,
        topic_similarity=cfg.topic_similarity,
        retention_horizon=cfg.retention_horizon,
        max_queries_per_doc=cfg.max_queries_per_doc,
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
    """FastAPI startup/shutdown hook. Runs when uvicorn starts and stops.

    Startup: build the pipeline, then emit a "service_start" info event — the
    dashboard shows these lifecycle events and uses them for reachability.
    Shutdown: emit "service_stop" and close the outbox (stops its thread).
    """
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
        emit("service_stop", "info", {"message": "VectorAnchor shutting down"})
        emit.close()


# The FastAPI application object. uvicorn (started by the Docker entrypoint or
# the run_local_demo.sh runner) imports this module and serves this app.
app = FastAPI(title="Project Black Monolith — VectorAnchor", lifespan=lifespan)


def _admin_credential_valid(expected: str | None, authorization: str) -> bool:
    """Constant-time comparison of the supplied bearer token against the
    expected MONOLITH_ADMIN_TOKEN. compare_digest avoids timing side channels.
    """
    if not expected or len(expected) < 16 or not authorization.startswith("Bearer "):
        return False
    supplied = authorization[len("Bearer ") :]
    return bool(supplied) and compare_digest(supplied, expected)


def _require_admin(request: Request) -> None:
    """Authenticate corpus and detector-state mutations.

    Called by /admin/add-documents, /quarantine, /stats, /admin/reset-detection.
    Deliberately separate from the ingest token: the person seeding the corpus
    is an operator, not a detection module, and corpus mutations change what
    the detector sees, so they need their own credential.

    Fail-closed behavior: if MONOLITH_ADMIN_TOKEN is not configured at all
    (or is too short), the endpoint answers 503 "unavailable" rather than
    pretending auth passed. A wrong token is a 401.
    """
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
    """Docker healthcheck target (docker-compose.yml probes /health). Returns
    ok whenever the process is up; it does not check ChromaDB."""
    return {
        "status": "ok",
        "module": MODULE_NAME,
    }


@app.post("/retrieve")
def retrieve(req: RetrieveRequest, request: Request) -> dict:
    """THE main endpoint: an agent's retrieval call, proxied and defended.

    Input:  body {query, k?} + X-Monolith-* correlation headers.
    Output: {query, results: [{id, document, distance}], withheld: [...],
             quarantine_size}.

    Flow: parse body -> read correlation headers into an EventContext
    (events.py context_from_headers) -> RetrieverProxy.retrieve() does the
    actual work (embed, query ChromaDB, record, quarantine, serve clean).
    The EventContext is passed through so any quarantine event emitted inside
    is stamped with this request's tenant/agent/session.
    """
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
    total = proxy.upsert_documents([(document.id, document.text) for document in req.documents])
    return {"added": len(req.documents), "total": total}


@app.get("/quarantine")
def quarantine(request: Request) -> dict:
    """Admin: list currently quarantined documents (id, reason, score,
    preview, time). The run_full_demo.sh script calls this after the poison
    attack to show what was caught."""
    _require_admin(request)
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


@app.get("/stats")
def stats(request: Request) -> dict:
    """Admin: module health. The dashboard Operations page calls this
    (dashboard/app/api/operations/route.ts, using MONOLITH_MODULE_ADMIN_TOKEN)
    to show corpus size, quarantine size, outbox delivery backlog, and the
    active detector configuration."""
    _require_admin(request)
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
    _require_admin(request)
    proxy: RetrieverProxy = app.state.proxy
    proxy.reset_detection()
    return {"status": "reset"}
