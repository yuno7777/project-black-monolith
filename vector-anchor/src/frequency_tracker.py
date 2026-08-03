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
        # Reverse index keeps eviction proportional to the documents returned
        # by the evicted query instead of scanning the entire corpus.
        self._query_docs: dict[int, set[str]] = {}
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
        self._query_docs[qid] = set(ranked_doc_ids)
        for doc_id in ranked_doc_ids:
            rec = self._docs.setdefault(doc_id, _DocRecord())
            rec.queries[qid] = query_embedding
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        while len(self._window) > self.window_size:
            old_qid = self._window.popleft()
            empty_docs: list[str] = []
            for doc_id in self._query_docs.pop(old_qid, set()):
                rec = self._docs.get(doc_id)
                if rec is None:
                    continue
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
            record = self._docs.pop(doc_id, None)
            if record is None:
                continue
            for query_id in record.queries:
                documents = self._query_docs.get(query_id)
                if documents is not None:
                    documents.discard(doc_id)

    def snapshot(self) -> dict:
        return {
            "version": 1,
            "next_query_id": self._next_query_id,
            "window": list(self._window),
            "documents": {
                doc_id: {str(query_id): embedding for query_id, embedding in record.queries.items()}
                for doc_id, record in self._docs.items()
            },
        }

    @classmethod
    def from_snapshot(
        cls,
        data: dict,
        *,
        min_distinct_topics: int,
        topic_similarity: float,
        window_size: int,
    ) -> "FrequencyTracker":
        if data.get("version") != 1:
            raise ValueError("unsupported frequency tracker state version")
        raw_window = data.get("window")
        raw_documents = data.get("documents")
        next_query_id = data.get("next_query_id")
        if (
            not isinstance(raw_window, list)
            or len(raw_window) > window_size
            or any(not isinstance(item, int) or item < 0 for item in raw_window)
            or len(set(raw_window)) != len(raw_window)
            or not isinstance(next_query_id, int)
            or next_query_id < 0
            or not isinstance(raw_documents, dict)
            or len(raw_documents) > 100_000
        ):
            raise ValueError("invalid frequency tracker state")
        window_ids = set(raw_window)
        if window_ids and next_query_id <= max(window_ids):
            raise ValueError("frequency tracker query sequence is not monotonic")

        tracker = cls(
            min_distinct_topics=min_distinct_topics,
            topic_similarity=topic_similarity,
            window_size=window_size,
        )
        tracker._window = deque(raw_window)
        tracker._next_query_id = next_query_id
        tracker._query_docs = {query_id: set() for query_id in raw_window}
        for raw_doc_id, raw_queries in raw_documents.items():
            if (
                not isinstance(raw_doc_id, str)
                or not raw_doc_id
                or len(raw_doc_id) > 128
                or not isinstance(raw_queries, dict)
                or len(raw_queries) > window_size
            ):
                raise ValueError("invalid persisted document frequency state")
            queries: dict[int, list[float]] = {}
            for raw_query_id, raw_embedding in raw_queries.items():
                try:
                    query_id = int(raw_query_id)
                except (TypeError, ValueError) as error:
                    raise ValueError("invalid persisted query id") from error
                if (
                    query_id not in window_ids
                    or not isinstance(raw_embedding, list)
                    or not 1 <= len(raw_embedding) <= 4096
                    or any(
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(value)
                        for value in raw_embedding
                    )
                ):
                    raise ValueError("invalid persisted query embedding")
                queries[query_id] = [float(value) for value in raw_embedding]
                tracker._query_docs[query_id].add(raw_doc_id)
            if queries:
                tracker._docs[raw_doc_id] = _DocRecord(queries=queries)
        return tracker
