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
from .content_guard import inspect_document
from .detector_state import DetectorStateStore
from .events import EventContext, is_session_revoked, now_ms
from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine, QuarantinedDoc

POLICY_VERSION = "vector-anchor/2"


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
        state_store: DetectorStateStore | None = None,
    ):
        self.collection = collection
        self.embed_fn = embed_fn
        self.tracker = tracker
        self.quarantine = quarantine
        self.cfg = cfg
        self.emit = emit
        self.state_store = state_store
        # FastAPI runs synchronous endpoints in a thread pool. Tracker and
        # quarantine updates form one detector decision and must not interleave
        # with another retrieval or an administrative reset.
        self._state_lock = threading.RLock()
        self._state_dirty = False
        self._last_state_flush_ms = 0
        # Sessions already refused once, so the refusal event is emitted once
        # per session instead of on every retrieval the agent retries.
        self._refused_sessions: set[str] = set()

    def retrieve(
        self,
        query: str,
        k: int | None = None,
        ctx: EventContext | None = None,
    ) -> dict[str, Any]:
        """`ctx` carries the caller's correlation identity for this one
        retrieval, so a quarantine here can be tied to detections the other
        layers made in the same agent session."""
        # The cross-layer circuit breaker revoked this session: the agent's
        # context is not trustworthy, so nothing from the corpus may be served
        # into it. Refuse before embedding or touching detector state.
        session_id = ctx.session_id if ctx else None
        if session_id and is_session_revoked(session_id):
            return self._refuse_revoked_session(query, session_id, ctx)

        start = now_ms()
        k = k or self.cfg.top_k
        # Embed once and pass the exact same vector to Chroma and the detector.
        # Using query_texts here would make Chroma invoke the embedding
        # function a second time and could even give the two decisions
        # different vectors for a non-deterministic remote embedder.
        # Semantic embedding providers return NumPy arrays; normalize the public
        # boundary for the tracker and Chroma alike.
        query_embedding = [float(value) for value in self.embed_fn([query])[0]]

        # Query and scoring share the same lock as corpus mutations.
        with self._state_lock:
            n = (
                k
                + self.cfg.candidate_buffer
                + min(len(self.quarantine.list_ids()), 64)
            )
            res = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n,
                include=["documents", "distances", "metadatas"],
            )
            ids = res["ids"][0]
            docs = res["documents"][0]
            dists = res["distances"][0]

            # Record the top-ranked documents for this query so cross-query
            # frequency can be judged. Only the genuinely top-ranked results
            # are recorded (a doc buried at rank 8 is not "ranking highly").
            top_ranked = ids[: self.cfg.top_rank_threshold]
            self.tracker.record_query(top_ranked, query_embedding)

            clean: list[dict[str, Any]] = []
            withheld: list[dict[str, Any]] = []
            newly_quarantined: list[str] = []

            for doc_id, document, distance in zip(ids, docs, dists, strict=True):
                if self.quarantine.is_quarantined(doc_id):
                    withheld.append({"id": doc_id, "reason": "already_quarantined"})
                    continue

                indicators = inspect_document(document or "")
                if indicators:
                    newly = self.quarantine.add(QuarantinedDoc(
                        doc_id=doc_id, reason="retrieved_instruction_indicators",
                        score=len(indicators), preview=(document or "")[:160],
                        quarantined_at_ms=now_ms(),
                    ))
                    if hasattr(self.tracker, "_quarantined"):
                        self.tracker._quarantined.add(doc_id)
                    if newly:
                        newly_quarantined.append(doc_id)
                    self.emit(
                        "corpus_poison_quarantine", "critical",
                        {"doc_id": doc_id, "indicators": indicators,
                         "document_sha256": _content_fingerprint(document or ""),
                         "document_chars": len(document or ""),
                         "detection_latency_ms": now_ms() - start},
                        ctx, resource_type="document", resource_id=doc_id,
                        outcome="quarantined", policy_version=POLICY_VERSION,
                    )
                    withheld.append({"id": doc_id, "reason": "retrieved_instruction_indicators"})
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
                    if hasattr(self.tracker, "_quarantined"):
                        self.tracker._quarantined.add(doc_id)
                    if newly:
                        newly_quarantined.append(doc_id)
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

                clean.append({"id": doc_id, "document": document, "distance": distance})

            served = clean[:k]
            quarantine_size = len(self.quarantine)
            self._persist_state(force=bool(newly_quarantined))

        if withheld or getattr(self.cfg, "log_clean_retrievals", True):
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

    def _refuse_revoked_session(
        self, query: str, session_id: str, ctx: EventContext | None
    ) -> dict[str, Any]:
        """Serve nothing to a session the circuit breaker revoked.

        The caller still gets a well-formed response so an agent framework can
        distinguish "revoked" from "no matches"; it just never gets corpus
        text.
        """
        with self._state_lock:
            already_reported = session_id in self._refused_sessions
            self._refused_sessions.add(session_id)
            quarantine_size = len(self.quarantine)
        if not already_reported:
            query_sha256 = _content_fingerprint(query)
            self.emit(
                "session_quarantined",
                "critical",
                {
                    "session_id": session_id,
                    "refusal": "retrieval",
                },
                ctx,
                resource_type="retrieval_query",
                resource_id=query_sha256,
                outcome="refused",
                policy_version=POLICY_VERSION,
            )
        return {
            "query": query,
            "results": [],
            "withheld": [],
            "quarantine_size": quarantine_size,
            "session_quarantined": True,
        }

    def quarantine_snapshot(self) -> list[QuarantinedDoc]:
        with self._state_lock:
            return self.quarantine.all()

    def quarantine_size(self) -> int:
        with self._state_lock:
            return len(self.quarantine)

    def release_quarantine(self, doc_id: str) -> dict[str, Any]:
        with self._state_lock:
            released = doc_id in self.quarantine.list_ids()
            self.quarantine.remove_many([doc_id])
            if hasattr(self.tracker, "reset_doc"):
                self.tracker.reset_doc(doc_id)
            else:
                self.tracker.forget_documents([doc_id])
            self._persist_state(force=True)
            quarantined_count = len(self.quarantine.list_ids())
        return {
            "doc_id": doc_id,
            "released": released,
            "quarantined_count": quarantined_count,
        }

    def reset_detection(self) -> None:
        with self._state_lock:
            self.tracker = FrequencyTracker(
                min_distinct_topics=self.cfg.min_distinct_topics,
                topic_similarity=self.cfg.topic_similarity,
                retention_horizon=self.cfg.retention_horizon,
                max_queries_per_doc=self.cfg.max_queries_per_doc,
                max_tracked_docs=getattr(self.cfg, "max_tracked_docs", 50_000),
            )
            self.quarantine = Quarantine()
            self._persist_state(force=True)

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
            self._persist_state(force=True)
            return self.collection.count()

    def flush_state(self) -> bool:
        with self._state_lock:
            if not self.state_store:
                self._state_dirty = False
                return False
            self._persist_state(force=True)
            return True

    def _persist_state(self, *, force: bool = False) -> None:
        if not self.state_store:
            return
        interval_ms = int(getattr(self.cfg, "state_flush_interval_ms", 0) or 0)
        current_ms = now_ms()
        if (
            force
            or interval_ms <= 0
            or (current_ms - self._last_state_flush_ms) >= interval_ms
        ):
            self.state_store.save(self.tracker, self.quarantine)
            self._last_state_flush_ms = current_ms
            self._state_dirty = False
        else:
            self._state_dirty = True
