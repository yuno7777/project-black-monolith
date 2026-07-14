"""Retrieval proxy: the single choke point every retrieval passes through.

For each query it pulls a few more candidates than requested, records the
top-ranked ones in the frequency tracker, quarantines any document that has
crossed the universal-bait threshold, and serves the next-best clean
documents in place of quarantined ones — so a poisoned document never
reaches the caller's (agent's) context.
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .events import now_ms
from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine, QuarantinedDoc


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

    def retrieve(self, query: str, k: int | None = None) -> dict[str, Any]:
        start = now_ms()
        k = k or self.cfg.top_k
        n = k + self.cfg.candidate_buffer

        res = self.collection.query(
            query_texts=[query],
            n_results=n,
            include=["documents", "distances", "metadatas"],
        )
        ids = res["ids"][0]
        docs = res["documents"][0]
        dists = res["distances"][0]

        query_embedding = self.embed_fn([query])[0]

        # Record the top-ranked documents for this query so cross-query
        # frequency can be judged. Only the genuinely top-ranked results are
        # recorded (a doc buried at rank 8 is not "ranking highly").
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
                            "preview": preview,
                            "detection_latency_ms": now_ms() - start,
                        },
                    )
                withheld.append({"id": doc_id, "reason": "quarantined_now"})
                continue

            clean.append(
                {"id": doc_id, "document": document, "distance": distance}
            )

        served = clean[:k]

        self.emit(
            "retrieval",
            "info",
            {
                "query": query,
                "returned": len(served),
                "withheld": len(withheld),
                "latency_ms": now_ms() - start,
            },
        )

        return {
            "query": query,
            "results": served,
            "withheld": withheld,
            "quarantine_size": len(self.quarantine),
        }
