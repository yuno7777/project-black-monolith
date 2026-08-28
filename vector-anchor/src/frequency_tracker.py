"""Retrieval-frequency anomaly detection.

WHAT THIS FILE IS
-----------------
The actual "detector brain" of VectorAnchor — the code that decides a document
is a corpus-poisoning "universal bait". Everything else in the module (main.py,
retriever_proxy.py, quarantine.py) is plumbing around this logic.

THE CORE IDEA (simple version)
------------------------------
A normal document is relevant to ONE topic, so it shows up in search results
for queries about that topic. A poison "bait" document is engineered to rank
highly for MANY unrelated topics, so no matter what the agent asks, the bait
lands in its context.

So the detector does NOT count how often a document appears. It counts how many
MUTUALLY DISSIMILAR topics the document appears for. Rank for 8 queries about
gardening -> 1 topic -> fine. Rank for 4 queries about completely different
things -> 4 topics -> poisoned.

THE TECHNICAL MECHANISM
-----------------------
- For every document, remember the embeddings of the queries it ranked top-2
  for (a query_id -> embedding map, capped at `max_queries_per_doc` entries).
- The "topic count" for a document is computed by greedy clustering: sort the
  stored query embeddings, then walk them, starting a new cluster whenever a
  query is not similar enough (cosine < `topic_similarity`) to any previous
  cluster representative. The number of clusters = the anomaly score.
- Score >= `min_distinct_topics` (4) -> the document is flagged, and
  retriever_proxy.py quarantines it.

WHY THE RETENTION DESIGN MATTERS (the interesting part)
-------------------------------------------------------
The detector used to keep a global window of the last N queries, which made the
detection horizon the same as the memory bound. An attacker could "slow drip":
surface the bait for one topic per window, let the old hits age out, and never
reach 4 topics inside any single window. Widening the window fixed that but made
clustering cost quadratic in window size.

Now retention is per document with two separate knobs:
  retention_horizon (500): how far back a hit still counts — the reach, and the
                           price an attacker pays (~500 covering queries per
                           hidden topic).
  max_queries_per_doc (8): the cap on stored hits — bounds memory and
                           clustering cost no matter how wide the horizon is.

And when the cap is hit, the evicted hit is the one the newest hit MOST
DUPLICATES, not the oldest. Reason: oldest-first lets an attacker flood the cap
with varied same-topic queries to push out the distinct topics a bait already
earned — a cheaper evasion than the drip itself. Evicting the most-duplicated
hit means a flood of similar queries evicts itself, and displacing a real topic
requires supplying a more distinct query, which RAISES the score.

WHY THIS FILE HAS NO CHROMADB DEPENDENCY
----------------------------------------
It operates purely on query vectors handed to it. That is what makes it
unit-testable in isolation (tests/test_frequency_tracker.py imports only this
module), and it is why the fixture calibration scripts can run offline.

Called from: retriever_proxy.py (record_query on every /retrieve,
is_anomalous/evaluate during result filtering) and main.py (constructs it,
loads/saves it via detector_state.py). See those files for the surrounding flow.
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
    """One document's stored memory: query_id -> query embedding.

    The key is an incrementing integer id (not the query text — we never keep
    raw query text, only its vector, for privacy). `queries` is capped at
    max_queries_per_doc entries by _admit/_evict_for.
    """

    # query_id -> query embedding, for queries where this doc ranked highly
    queries: dict[int, list[float]] = field(default_factory=dict)


@dataclass
class AnomalyResult:
    """The scoring result for one document, used by retriever_proxy.py when it
    emits a corpus_poison_quarantine event (score, distinct_topics,
    total_queries go into the event's details)."""

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
        """Construct with the CALIBRATED thresholds (from config.py, which in
        turn gets them from env / fixtures/calibrate.py).

        Args:
          min_distinct_topics: flag a doc that ranks across >= this many
                               dissimilar topic clusters (default 4).
          topic_similarity:    cosine threshold for "same topic" (default 0.20).
          retention_horizon:   how many queries back a hit still counts (500).
          max_queries_per_doc: max stored hits per doc (8).
        """
        self.min_distinct_topics = min_distinct_topics
        self.topic_similarity = topic_similarity
        self.retention_horizon = retention_horizon
        self.max_queries_per_doc = max_queries_per_doc
        # doc_id -> its query history. This is the whole detector's memory.
        self._docs: dict[str, _DocRecord] = {}
        # Monotonic counter assigning each recorded query a unique integer id.
        # Used for both horizon pruning (id < cutoff is expired) and ordering.
        self._next_query_id = 0

    # -- recording ---------------------------------------------------------

    def record_query(
        self, ranked_doc_ids: list[str], query_embedding: list[float]
    ) -> None:
        """Record that ``ranked_doc_ids`` (already limited to the top ranks)
        were returned for a query with ``query_embedding``.

        Called from: retriever_proxy.py retrieve() — every /retrieve request
        passes the top-ranked doc ids and the query's embedding here.

        Steps: validate the embedding is finite -> normalize it ONCE (so every
        later similarity check is a plain dot product, not a cosine
        recomputation) -> assign the query an id -> for each doc that ranked
        highly: prune hits older than the horizon, then admit (cap + evict if
        needed). Every 1000th query also triggers a sweep that deletes
        documents with no live hits left.
        """
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
        """Add a hit to a document's record, enforcing the per-doc cap."""
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

        Step by step: compare the NEW embedding to every stored one (except
        itself), remember the stored hit with the HIGHEST similarity (ties go
        to the older entry so eviction is deterministic), delete that one.
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
        """Delete a document's hits whose query id is older than the horizon.
        Runs when the document is touched (record_query), not on a timer."""
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
        """The query embeddings that are still inside the horizon. Scoring and
        pruning use the same cutoff, so they can never disagree."""
        cutoff = self._cutoff()
        return [emb for qid, emb in rec.queries.items() if qid >= cutoff]

    def distinct_topic_count(self, doc_id: str) -> int:
        """Greedily cluster the queries a document ranked for by similarity,
        and count the clusters. Unrelated queries fall into separate
        clusters, so a broadly-baiting document scores high.

        Step by step:
          1. Get the live (in-horizon) query embeddings for the document.
          2. Sort them (deterministic order — greedy clustering depends on
             encounter order, and sorting makes the score stable even when
             concurrent requests arrive in different orders).
          3. Walk the sorted list. A query joins an existing cluster if its
             dot product with ANY cluster representative >= topic_similarity;
             otherwise it starts a new cluster.
          4. The number of clusters is the topic count.

        Called from: retriever_proxy.py (is_anomalous on every candidate,
        evaluate when flagging) and tests.
        """
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
        """Full scoring result for a flagged document.

        Called from: retriever_proxy.py when is_anomalous() returns True, so
        the quarantine event can carry score + topic count + total queries.
        """
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
        """THE decision function: has this document crossed the threshold?

        Called from: retriever_proxy.py for every candidate document of every
        /retrieve. Returns True -> the doc gets quarantined.
        """
        return self.distinct_topic_count(doc_id) >= self.min_distinct_topics

    def forget_documents(self, doc_ids: list[str]) -> None:
        """Discard history for documents whose corpus content was replaced.

        Called from: retriever_proxy.py upsert_documents(). Keeping old
        frequency/quarantine decisions for replaced content would either block
        a remediated document or condemn the new version with the old one's
        history.
        """
        for doc_id in doc_ids:
            self._docs.pop(doc_id, None)

    # -- persistence -------------------------------------------------------

    def snapshot(self) -> dict:
        """Serialize the tracker for detector_state.py (which writes it
        atomically to detector_state.json after every retrieval).

        Version 2 = per-document retention semantics. Version 1 (a global
        window) is refused on load because its numbers mean something
        different.
        """
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
        """Rebuild a tracker from saved state. Called by
        detector_state.py load(), which is called by main.py at startup.

        The validation here is deliberately strict: the file on disk is
        treated as untrusted input (someone could edit it), and a state that
        fails validation raises ValueError so main.py can quarantine the file
        aside and start fresh instead of crashing in a loop.
        """
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
