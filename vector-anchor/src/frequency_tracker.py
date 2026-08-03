"""Retrieval-frequency anomaly detection.

Tracks, per document, the set of queries for which that document appeared in
the top ranks. A legitimate document is relevant to one topic and so appears
only for queries about that topic. A corpus-poisoning "universal bait"
document is engineered to rank highly for many *unrelated* queries — so the
telling signal is not raw frequency but appearing across many mutually
DISSIMILAR queries.

The anomaly score for a document is the number of distinct topics (clusters
of mutually similar queries) it has ranked highly for. Crossing
``min_distinct_topics`` flags the document.

Retention: per-document, not global
-----------------------------------
This detector used to keep a *global* rolling window of the last N queries.
That bounded memory, but it also bounded the detection horizon to N queries
for every document at once — which is precisely what the slow-drip evasion
exploited: surface the bait for one topic per window, let the earlier hit age
out, and the count never reaches the threshold (measured: peak 1 against a
threshold of 4 while covering 12 topics).

Widening the global window closes that, but naively: clustering is quadratic
in the number of queries retained *per document*, so a 10x wider window costs
100x more per retrieval. The horizon and the cost were the same knob.

They are now separate knobs:

* ``retention_horizon`` — how many queries back a hit still counts. This is
  the detection horizon, and it is what prices the slow drip.
* ``max_queries_per_doc`` — the most hits retained for any one document.
  This is what bounds memory and clustering cost, independent of the horizon.

When the cap is reached the *most redundant* retained hit is dropped, not the
oldest, so ordinary repeated traffic evicts itself rather than pushing out the
distinct topics a document has genuinely ranked for.

This module is pure Python (given query vectors) and has no ChromaDB
dependency, so the detection logic is unit-testable in isolation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .embedding import normalize, unit_dot

# Documents that stop being retrieved would otherwise keep expired entries
# forever, since pruning happens when a document is touched. Sweep occasionally
# instead of scanning every document on every query.
SWEEP_INTERVAL = 1000


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
        retention_horizon: int,
        max_queries_per_doc: int,
    ):
        self.min_distinct_topics = min_distinct_topics
        self.topic_similarity = topic_similarity
        self.retention_horizon = retention_horizon
        self.max_queries_per_doc = max_queries_per_doc
        self._docs: dict[str, _DocRecord] = {}
        self._next_query_id = 0

    # -- recording ---------------------------------------------------------

    def record_query(
        self, ranked_doc_ids: list[str], query_embedding: list[float]
    ) -> None:
        """Record that ``ranked_doc_ids`` (already limited to the top ranks)
        were returned for a query with ``query_embedding``."""
        if not query_embedding or not all(
            math.isfinite(value) for value in query_embedding
        ):
            raise ValueError("query embedding must be non-empty and finite")
        # Do not retain a caller-owned mutable list as detector state, and
        # normalize once here so every later comparison is a dot product.
        query_embedding = normalize(query_embedding)
        qid = self._next_query_id
        self._next_query_id += 1
        for doc_id in ranked_doc_ids:
            rec = self._docs.setdefault(doc_id, _DocRecord())
            self._prune_expired(rec)
            self._admit(rec, qid, query_embedding)
        if qid % SWEEP_INTERVAL == 0:
            self._sweep()

    def _admit(self, rec: _DocRecord, qid: int, embedding: list[float]) -> None:
        rec.queries[qid] = embedding
        while len(rec.queries) > self.max_queries_per_doc:
            self._evict_for(rec, qid, embedding)

    def _evict_for(self, rec: _DocRecord, qid: int, embedding: list[float]) -> None:
        """Drop the retained hit that the newest one most duplicates.

        Evicting the *oldest* would be simpler and is wrong: an attacker whose
        bait already holds several distinct topics could flush them by making
        it rank for a burst of merely-varied queries in one topic, cheaply
        resetting the score. Evicting what the new hit duplicates means a flood
        of similar queries evicts itself, and pushing out a real topic requires
        supplying an even more distinct one — which raises the score.

        Scanning only against the new entry keeps this O(n) per admission. The
        exhaustive most-redundant-pair search is O(n^2) and, measured, cost
        ~30x the entire pre-existing detection budget.
        """
        drop, best = None, None
        for candidate_qid, candidate in rec.queries.items():
            if candidate_qid == qid:
                continue
            similarity = unit_dot(embedding, candidate)
            # Ties break toward the older entry so eviction is deterministic.
            if best is None or similarity > best:
                best, drop = similarity, candidate_qid
        if drop is not None:
            del rec.queries[drop]

    def _cutoff(self) -> int:
        """Oldest query id still within the horizon.

        One definition, used by both pruning and scoring, so the two cannot
        disagree about what "retained" means — the boundary is inclusive, so a
        horizon of N retains exactly the last N queries.
        """
        return self._next_query_id - self.retention_horizon

    def _prune_expired(self, rec: _DocRecord) -> None:
        cutoff = self._cutoff()
        for qid in [qid for qid in rec.queries if qid < cutoff]:
            del rec.queries[qid]

    def _sweep(self) -> None:
        """Drop records whose every hit has expired. High-cardinality clean
        traffic should not leave one empty record per document forever."""
        for doc_id in list(self._docs):
            rec = self._docs[doc_id]
            self._prune_expired(rec)
            if not rec.queries:
                del self._docs[doc_id]

    # -- scoring -----------------------------------------------------------

    def _live_embeddings(self, rec: _DocRecord) -> list[list[float]]:
        cutoff = self._cutoff()
        return [emb for qid, emb in rec.queries.items() if qid >= cutoff]

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
        embeddings = sorted(self._live_embeddings(rec), key=tuple)
        for emb in embeddings:
            if any(unit_dot(emb, rep) >= self.topic_similarity for rep in cluster_reps):
                continue
            cluster_reps.append(emb)
        return len(cluster_reps)

    def evaluate(self, doc_id: str) -> AnomalyResult:
        rec = self._docs.get(doc_id)
        total = len(self._live_embeddings(rec)) if rec else 0
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

    # -- persistence -------------------------------------------------------

    def snapshot(self) -> dict:
        return {
            "version": 2,
            "next_query_id": self._next_query_id,
            "documents": {
                doc_id: {
                    str(query_id): embedding
                    for query_id, embedding in record.queries.items()
                }
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
        retention_horizon: int,
        max_queries_per_doc: int,
    ) -> FrequencyTracker:
        # Version 1 held a global query window whose semantics no longer exist.
        # Refusing it is deliberate: silently reinterpreting old state under new
        # retention rules would produce scores nobody can reproduce.
        if data.get("version") != 2:
            raise ValueError("unsupported frequency tracker state version")
        raw_documents = data.get("documents")
        next_query_id = data.get("next_query_id")
        if (
            not isinstance(next_query_id, int)
            or isinstance(next_query_id, bool)
            or next_query_id < 0
            or not isinstance(raw_documents, dict)
            or len(raw_documents) > 100_000
        ):
            raise ValueError("invalid frequency tracker state")

        tracker = cls(
            min_distinct_topics=min_distinct_topics,
            topic_similarity=topic_similarity,
            retention_horizon=retention_horizon,
            max_queries_per_doc=max_queries_per_doc,
        )
        tracker._next_query_id = next_query_id
        for raw_doc_id, raw_queries in raw_documents.items():
            if (
                not isinstance(raw_doc_id, str)
                or not raw_doc_id
                or len(raw_doc_id) > 128
                or not isinstance(raw_queries, dict)
                or len(raw_queries) > max_queries_per_doc
            ):
                raise ValueError("invalid persisted document frequency state")
            queries: dict[int, list[float]] = {}
            for raw_query_id, raw_embedding in raw_queries.items():
                try:
                    query_id = int(raw_query_id)
                except (TypeError, ValueError) as error:
                    raise ValueError("invalid persisted query id") from error
                if (
                    not 0 <= query_id < next_query_id
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
                queries[query_id] = normalize([float(value) for value in raw_embedding])
            if queries:
                tracker._docs[raw_doc_id] = _DocRecord(queries=queries)
        return tracker
