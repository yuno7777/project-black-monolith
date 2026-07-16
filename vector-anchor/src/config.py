"""VectorAnchor configuration, sourced from environment variables.

VectorAnchor is the memory-layer defense of Project Black Monolith. It wraps
a vector-database retriever and quarantines corpus-poisoning documents that
rank highly across many unrelated queries ("universal bait") before they can
reach an agent's context window.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

MODULE_NAME = "vector-anchor"


@dataclass(frozen=True)
class Config:
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
    # Rolling window size, in number of most-recent queries retained.
    window_size: int

    # --- dashboard integration ------------------------------------------
    dashboard_url: str | None
    event_token: str | None
    event_outbox_path: str


def load_config() -> Config:
    return Config(
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
        window_size=int(os.environ.get("MONOLITH_WINDOW_SIZE", "50")),
        dashboard_url=os.environ.get("MONOLITH_DASHBOARD_URL") or None,
        event_token=os.environ.get("MONOLITH_EVENT_TOKEN") or None,
        event_outbox_path=os.environ.get("MONOLITH_EVENT_OUTBOX_PATH", "./event_outbox.db"),
    )
