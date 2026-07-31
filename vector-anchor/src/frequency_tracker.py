"""Retrieval-frequency anomaly detection.

Tracks, per document, the set of queries for which that document appeared in
the top ranks. A legitimate document is relevant to one topic and so appears
only for queries about that topic. A corpus-poisoning "universal bait"
document is engineered to rank highly for many *unrelated* queries — so the
telling signal is not raw frequency but appearing across many mutually
DISSIMILAR queries.

The anomaly score for a document is the number of distinct topics (clusters
of mutually similar queries) it has ranked highly for within a rolling
window. Crossing ``min_distinct_topics`` flags the document.

This module is pure Python (given query vectors) and has no ChromaDB
dependency, so the detection logic is unit-testable in isolation.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import math

from .embedding import cosine


@dataclass
class _DocRecord:
    # query_id -> query embedding, for queries where this doc ranked highly
    queries: dict[int, list[float]] = field(default_factory=dict)


@dataclass
class AnomalyResult:
    doc_id: str
    score: int  # number of distinct dissimilar topics
    distinct_topics: int
    total_queries: int


class FrequencyTracker:
    def __init__(
        self,
        *,
        min_distinct_topics: int,
        topic_similarity: float,
        window_size: int,
    ):
        self.min_distinct_topics = min_distinct_topics
        self.topic_similarity = topic_similarity
        self.window_size = window_size
        self._docs: dict[str, _DocRecord] = {}
        # Rolling window of query ids; evicting the oldest also removes its
        # contribution from every document record.
        self._window: deque[int] = deque()
        self._next_query_id = 0

    def record_query(
        self, ranked_doc_ids: list[str], query_embedding: list[float]
    ) -> None:
        """Record that ``ranked_doc_ids`` (already limited to the top ranks)
        were returned for a query with ``query_embedding``."""
        if not query_embedding or not all(
            math.isfinite(value) for value in query_embedding
        ):
            raise ValueError("query embedding must be non-empty and finite")
        # Do not retain a caller-owned mutable list as detector state.
        query_embedding = list(query_embedding)
        qid = self._next_query_id
        self._next_query_id += 1
        self._window.append(qid)
        for doc_id in ranked_doc_ids:
            rec = self._docs.setdefault(doc_id, _DocRecord())
            rec.queries[qid] = query_embedding
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        while len(self._window) > self.window_size:
            old_qid = self._window.popleft()
            empty_docs: list[str] = []
            for doc_id, rec in self._docs.items():
                rec.queries.pop(old_qid, None)
                if not rec.queries:
                    empty_docs.append(doc_id)
            # High-cardinality clean traffic should not leave one empty record
            # per document forever after its only query ages out.
            for doc_id in empty_docs:
                del self._docs[doc_id]

    def distinct_topic_count(self, doc_id: str) -> int:
        """Greedily cluster the queries a document ranked for by similarity,
        and count the clusters. Unrelated queries fall into separate
        clusters, so a broadly-baiting document scores high."""
        rec = self._docs.get(doc_id)
        if not rec:
            return 0
        cluster_reps: list[list[float]] = []
        # Greedy clustering depends on which representative is encountered
        # first. Sort the vectors so identical traffic produces the same score
        # even when concurrent requests arrive in a different order.
        embeddings = sorted(rec.queries.values(), key=tuple)
        for emb in embeddings:
            if any(cosine(emb, rep) >= self.topic_similarity for rep in cluster_reps):
                continue
            cluster_reps.append(emb)
        return len(cluster_reps)

    def evaluate(self, doc_id: str) -> AnomalyResult:
        rec = self._docs.get(doc_id)
        total = len(rec.queries) if rec else 0
        topics = self.distinct_topic_count(doc_id)
        return AnomalyResult(
            doc_id=doc_id,
            score=topics,
            distinct_topics=topics,
            total_queries=total,
        )

    def is_anomalous(self, doc_id: str) -> bool:
        return self.distinct_topic_count(doc_id) >= self.min_distinct_topics

    def forget_documents(self, doc_ids: list[str]) -> None:
        """Discard history for documents whose corpus content was replaced."""
        for doc_id in doc_ids:
            self._docs.pop(doc_id, None)
