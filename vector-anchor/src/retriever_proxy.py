"""Retrieval proxy: the single choke point every retrieval passes through.

For each query it pulls a few more candidates than requested, records the
top-ranked ones in the frequency tracker, quarantines any document that has
crossed the universal-bait threshold, and serves the next-best clean
documents in place of quarantined ones — so a poisoned document never
reaches the caller's (agent's) context.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any

from .config import Config
from .events import EventContext, now_ms
from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine, QuarantinedDoc

POLICY_VERSION = "vector-anchor/1"


def _content_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RetrieverProxy:
    def __init__(
        self,
        *,
        collection,
        embed_fn,
        tracker: FrequencyTracker,
        quarantine: Quarantine,
        cfg: Config,
        emit,
    ):
        self.collection = collection
        self.embed_fn = embed_fn
        self.tracker = tracker
        self.quarantine = quarantine
        self.cfg = cfg
        self.emit = emit
        # FastAPI runs synchronous endpoints in a thread pool. Tracker and
        # quarantine updates form one detector decision and must not interleave
        # with another retrieval or an administrative reset.
        self._state_lock = threading.RLock()

    def retrieve(
        self,
        query: str,
        k: int | None = None,
        ctx: EventContext | None = None,
    ) -> dict[str, Any]:
        """`ctx` carries the caller's correlation identity for this one
        retrieval, so a quarantine here can be tied to detections the other
        layers made in the same agent session."""
        start = now_ms()
        k = k or self.cfg.top_k
        n = k + self.cfg.candidate_buffer
        # Embed once and pass the exact same vector to Chroma and the detector.
        # Using query_texts here would make Chroma invoke the embedding
        # function a second time and could even give the two decisions
        # different vectors for a non-deterministic remote embedder.
        query_embedding = self.embed_fn([query])[0]

        res = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n,
            include=["documents", "distances", "metadatas"],
        )
        ids = res["ids"][0]
        docs = res["documents"][0]
        dists = res["distances"][0]

        with self._state_lock:
            # Record the top-ranked documents for this query so cross-query
            # frequency can be judged. Only the genuinely top-ranked results
            # are recorded (a doc buried at rank 8 is not "ranking highly").
            top_ranked = ids[: self.cfg.top_rank_threshold]
            self.tracker.record_query(top_ranked, query_embedding)

            clean: list[dict[str, Any]] = []
            withheld: list[dict[str, Any]] = []

            for doc_id, document, distance in zip(ids, docs, dists):
                if self.quarantine.is_quarantined(doc_id):
                    withheld.append({"id": doc_id, "reason": "already_quarantined"})
                    continue

                # Has this document now crossed the universal-bait threshold?
                if self.tracker.is_anomalous(doc_id):
                    result = self.tracker.evaluate(doc_id)
                    preview = (document or "")[:160]
                    qd = QuarantinedDoc(
                        doc_id=doc_id,
                        reason="universal_bait_frequency_anomaly",
                        score=result.score,
                        preview=preview,
                        quarantined_at_ms=now_ms(),
                    )
                    newly = self.quarantine.add(qd)
                    if newly:
                        self.emit(
                            "corpus_poison_quarantine",
                            "critical",
                            {
                                "doc_id": doc_id,
                                "anomaly_score": result.score,
                                "distinct_topics": result.distinct_topics,
                                "threshold": self.cfg.min_distinct_topics,
                                "total_queries_seen": result.total_queries,
                                # Corpus text is untrusted and may itself contain
                                # credentials or personal data. Keep the readable
                                # preview behind the admin-only quarantine route;
                                # telemetry gets a stable fingerprint instead.
                                "document_sha256": _content_fingerprint(document or ""),
                                "document_chars": len(document or ""),
                                "detection_latency_ms": now_ms() - start,
                            },
                            ctx,
                            resource_type="document",
                            resource_id=doc_id,
                            outcome="quarantined",
                            policy_version=POLICY_VERSION,
                        )
                    withheld.append({"id": doc_id, "reason": "quarantined_now"})
                    continue

                clean.append(
                    {"id": doc_id, "document": document, "distance": distance}
                )

            served = clean[:k]
            quarantine_size = len(self.quarantine)

        query_sha256 = _content_fingerprint(query)
        self.emit(
            "retrieval",
            "info",
            {
                # Queries often carry end-user text or secrets from an agent's
                # context. Preserve repeat-correlation without copying their
                # contents into stderr, the outbox, and the event ledger.
                "query_sha256": query_sha256,
                "query_chars": len(query),
                "returned": len(served),
                "withheld": len(withheld),
                "latency_ms": now_ms() - start,
            },
            ctx,
            resource_type="retrieval_query",
            resource_id=query_sha256,
            outcome="filtered" if withheld else "served",
            policy_version=POLICY_VERSION,
        )

        return {
            "query": query,
            "results": served,
            "withheld": withheld,
            "quarantine_size": quarantine_size,
        }

    def quarantine_snapshot(self) -> list[QuarantinedDoc]:
        with self._state_lock:
            return self.quarantine.all()

    def quarantine_size(self) -> int:
        with self._state_lock:
            return len(self.quarantine)

    def reset_detection(self) -> None:
        with self._state_lock:
            self.tracker = FrequencyTracker(
                min_distinct_topics=self.cfg.min_distinct_topics,
                topic_similarity=self.cfg.topic_similarity,
                window_size=self.cfg.window_size,
            )
            self.quarantine = Quarantine()

    def upsert_documents(self, documents: list[tuple[str, str]]) -> int:
        """Replace corpus documents and invalidate detector state atomically.

        Frequency and quarantine decisions describe specific content. Keeping
        them after an administrator replaces that content would either leave a
        remediated document blocked or immediately condemn the new version
        using the old version's history.
        """
        ids = [doc_id for doc_id, _ in documents]
        with self._state_lock:
            self.collection.upsert(
                ids=ids,
                documents=[text for _, text in documents],
            )
            self.tracker.forget_documents(ids)
            self.quarantine.remove_many(ids)
            return self.collection.count()
