"""VectorAnchor configuration, sourced from environment variables.

WHAT THIS FILE IS
-----------------
The single place that reads VectorAnchor's environment variables, validates
them, and produces one frozen `Config` object that the rest of the module
imports. Every service setting — the ChromaDB location, the detector thresholds,
the dashboard URL — flows through load_config() so the rest of the code never
touches os.environ directly.

WHY IT EXISTS
-------------
1. Fail fast at startup: a typo like MONOLITH_TOP_K="abc" crashes here with a
   clear message instead of failing mysteriously at first use.
2. One source of truth: retriever_proxy.py, store.py, main.py and the tests all
   read the same validated Config.
3. It documents every knob in one place — compare with trace-audit/src/config.py
   which is the same pattern for the reasoning layer, and mcp-shield's
   ShieldConfig::from_env in proxy.rs (the Rust equivalent).

Data flow: environment -> load_config() -> Config -> passed to RetrieverProxy,
DetectorStateStore, build_embedding_function etc. at startup in main.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

MODULE_NAME = "vector-anchor"
MAX_ID_LENGTH = 128


@dataclass(frozen=True)
class Config:
    """All runtime settings, validated. Immutable (frozen) so nothing can
    silently change a threshold mid-run.

    The detection parameters deserve an explanation because they ARE the
    detector — see frequency_tracker.py for the algorithm these tune:

      top_rank_threshold:  how far down the result list a document still counts
                           as "ranking highly" for a query. Default 2.
      min_distinct_topics: how many mutually dissimilar topics a document must
                           rank across before it is quarantined. Default 4.
      topic_similarity:    two queries are "the same topic" if their cosine
                           similarity is >= this. Default 0.20.
      retention_horizon:   how many queries back a hit still counts (the
                           detection reach). Default 500.
      max_queries_per_doc: the most hits kept per document (bounds memory and
                           clustering cost). Default 8.

    The horizon and the cap are deliberately SEPARATE knobs: widening the
    horizon used to make detection cost quadratic, and separating them is what
    lets the detector reach 10x further back for 1.5x the cost. The numbers are
    calibrated in vector-anchor/fixtures/calibrate.py, not guessed.
    """

    # --- vector store ---------------------------------------------------
    chroma_path: str
    collection_name: str
    # "hash" (default) uses a lightweight, dependency-free, deterministic
    # hashing embedder so the demo runs fully offline and reproducibly.
    # "default" uses ChromaDB's built-in sentence-transformers model (better
    # semantic quality, but downloads a model on first use).
    embedding: str
    embedding_dim: int

    # --- retrieval ------------------------------------------------------
    top_k: int
    # How many extra candidates to pull below top_k so a quarantined doc can
    # be transparently replaced by the next-best clean result.
    candidate_buffer: int

    # --- frequency-anomaly detection ------------------------------------
    # A document is flagged as universal bait when it appears in the top
    # `top_rank_threshold` results for at least `min_distinct_topics`
    # mutually dissimilar queries within the rolling window.
    top_rank_threshold: int
    min_distinct_topics: int
    # Two queries count as the "same topic" when their cosine similarity is
    # at or above this value; below it they are treated as unrelated.
    topic_similarity: float
    # How many queries back a hit still counts toward a document's topic
    # score. This is the detection horizon and what prices the slow drip.
    retention_horizon: int
    # Most hits retained for any one document. Bounds memory and the
    # quadratic clustering cost independently of the horizon.
    max_queries_per_doc: int

    # --- dashboard integration ------------------------------------------
    dashboard_url: str | None
    event_token: str | None
    event_outbox_path: str
    detector_state_path: str
    admin_token: str | None

    # --- correlation ----------------------------------------------------
    # Process-level defaults for who the detections belong to. A per-request
    # X-Monolith-* header overrides them, which is how one service serving many
    # agents attributes each detection correctly. Both are None unless
    # configured: an invented session id would group unrelated agents together,
    # and the grouping is the entire point of having one.
    tenant_id: str
    agent_id: str | None
    session_id: str | None


def _valid_bearer_token(value: str) -> bool:
    """A token must be >= 16 chars of header-safe characters.

    Header-safe means it cannot contain whitespace or characters that would
    break the Authorization header. The dashboard enforces the same rule
    (dashboard/lib/credentials.ts), so a token that passes here will pass there.
    """
    return len(value) >= 16 and all(
        char.isascii() and (char.isalnum() or char in "-._~+/=")
        for char in value
    )


def _validate_id(name: str, value: str | None, *, required: bool = False) -> None:
    """Correlation ids (tenant/agent/session) must be 1-128 non-blank chars.

    Mirrors the dashboard's own bounds (dashboard/lib/event-store.ts
    identityText) so an id that passes here can never be rejected later.
    """
    if value is None and not required:
        return
    if value is None or not value.strip() or len(value.strip()) > MAX_ID_LENGTH:
        raise ValueError(f"{name} must be between 1 and {MAX_ID_LENGTH} characters")


def _validate_config(cfg: Config) -> Config:
    """Cross-field validation. Each check maps to a documented env var and
    fails startup with the variable's name rather than a mystery error."""
    if cfg.embedding not in {"hash", "default"}:
        raise ValueError("MONOLITH_EMBEDDING must be 'hash' or 'default'")
    if not 1 <= cfg.embedding_dim <= 4096:
        raise ValueError("MONOLITH_EMBEDDING_DIM must be between 1 and 4096")
    if not 1 <= cfg.top_k <= 100:
        raise ValueError("MONOLITH_TOP_K must be between 1 and 100")
    if not 0 <= cfg.candidate_buffer <= 1000:
        raise ValueError("MONOLITH_CANDIDATE_BUFFER must be between 0 and 1000")
    if not 1 <= cfg.top_rank_threshold <= cfg.top_k + cfg.candidate_buffer:
        raise ValueError(
            "MONOLITH_TOP_RANK_THRESHOLD must fit within the retrieval candidate set"
        )
    if not 1 <= cfg.retention_horizon <= 1_000_000:
        raise ValueError("MONOLITH_RETENTION_HORIZON must be between 1 and 1000000")
    if not 1 <= cfg.max_queries_per_doc <= 4096:
        raise ValueError("MONOLITH_MAX_QUERIES_PER_DOC must be between 1 and 4096")
    if not 1 <= cfg.min_distinct_topics <= cfg.max_queries_per_doc:
        raise ValueError(
            "MONOLITH_MIN_DISTINCT_TOPICS must be between 1 and max queries per document"
        )
    if not -1.0 <= cfg.topic_similarity <= 1.0:
        raise ValueError("MONOLITH_TOPIC_SIMILARITY must be between -1 and 1")
    if not cfg.collection_name.strip():
        raise ValueError("MONOLITH_COLLECTION must not be blank")
    if not cfg.chroma_path.strip():
        raise ValueError("MONOLITH_CHROMA_PATH must not be blank")
    if not cfg.detector_state_path.strip():
        raise ValueError("MONOLITH_DETECTOR_STATE_PATH must not be blank")
    # URL and token must come as a pair: sending events with no token would
    # mean every POST 401s and dead-letters on arrival (burning disk for
    # nothing), so the module refuses to start in that half-configured state.
    if bool(cfg.dashboard_url) != bool(cfg.event_token):
        raise ValueError(
            "MONOLITH_DASHBOARD_URL and MONOLITH_EVENT_TOKEN must be configured together"
        )
    if cfg.dashboard_url and not cfg.dashboard_url.startswith(("http://", "https://")):
        raise ValueError("MONOLITH_DASHBOARD_URL must use http:// or https://")
    if cfg.event_token and not _valid_bearer_token(cfg.event_token):
        raise ValueError("MONOLITH_EVENT_TOKEN must be a header-safe token of at least 16 characters")
    if cfg.admin_token and not _valid_bearer_token(cfg.admin_token):
        raise ValueError("MONOLITH_ADMIN_TOKEN must be a header-safe token of at least 16 characters")
    _validate_id("MONOLITH_TENANT_ID", cfg.tenant_id, required=True)
    _validate_id("MONOLITH_AGENT_ID", cfg.agent_id)
    _validate_id("MONOLITH_SESSION_ID", cfg.session_id)
    return cfg


def load_config() -> Config:
    """Read every env var (with sane defaults), then validate the result.

    Called from:
      - vector-anchor/src/main.py      (build_proxy() -> load_config())
      - vector-anchor/fixtures/*.py    (seed_corpus.py, inject_poison.py,
        calibrate.py, benchmark.py all build the same Config so the fixtures
        talk to the same collection with the same embedder as the service)
      - vector-anchor/tests/test_config.py

    The defaults (top_rank_threshold=2, topic_similarity=0.20,
    min_distinct_topics=4) are the CALIBRATED values: the original (3, 0.30)
    let broad-but-legitimate documents score higher than the poison, and the
    sweep that fixed it is documented in fixtures/calibration_results.md.
    """
    cfg = Config(
        chroma_path=os.environ.get("MONOLITH_CHROMA_PATH", "./chroma_store"),
        collection_name=os.environ.get("MONOLITH_COLLECTION", "monolith_corpus"),
        embedding=os.environ.get("MONOLITH_EMBEDDING", "hash").strip().lower(),
        embedding_dim=int(os.environ.get("MONOLITH_EMBEDDING_DIM", "256")),
        top_k=int(os.environ.get("MONOLITH_TOP_K", "3")),
        candidate_buffer=int(os.environ.get("MONOLITH_CANDIDATE_BUFFER", "5")),
        # top_rank_threshold and topic_similarity were tuned from a
        # false-positive sweep (see fixtures/calibrate.py /
        # fixtures/calibration_results.md). The original (3, 0.30) let broad
        # single-domain documents accumulate up to 7 distinct "topics" — more
        # than the poison's score of 5 — an unfixable overlap. At (2, 0.20)
        # the highest clean document scores 2 and the poison scores 4, a
        # clean 2-topic separation. See README "Threshold calibration".
        top_rank_threshold=int(os.environ.get("MONOLITH_TOP_RANK_THRESHOLD", "2")),
        min_distinct_topics=int(os.environ.get("MONOLITH_MIN_DISTINCT_TOPICS", "4")),
        topic_similarity=float(os.environ.get("MONOLITH_TOPIC_SIMILARITY", "0.20")),
        retention_horizon=int(os.environ.get("MONOLITH_RETENTION_HORIZON", "500")),
        max_queries_per_doc=int(os.environ.get("MONOLITH_MAX_QUERIES_PER_DOC", "8")),
        dashboard_url=os.environ.get("MONOLITH_DASHBOARD_URL") or None,
        event_token=os.environ.get("MONOLITH_EVENT_TOKEN") or None,
        event_outbox_path=os.environ.get("MONOLITH_EVENT_OUTBOX_PATH", "./event_outbox.db"),
        detector_state_path=os.environ.get(
            "MONOLITH_DETECTOR_STATE_PATH", "./detector_state.json"
        ),
        admin_token=os.environ.get("MONOLITH_ADMIN_TOKEN") or None,
        tenant_id=os.environ.get("MONOLITH_TENANT_ID", "default"),
        agent_id=os.environ.get("MONOLITH_AGENT_ID") or None,
        session_id=os.environ.get("MONOLITH_SESSION_ID") or None,
    )
    return _validate_config(cfg)
