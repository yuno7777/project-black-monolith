"""Retrieval proxy: the single choke point every retrieval passes through.

WHAT THIS FILE IS
-----------------
The middle layer of VectorAnchor. main.py hands it the ChromaDB collection,
the embedding function, the FrequencyTracker, the Quarantine store, the
config, and the event emitter — and from then on, every /retrieve request
flows through RetrieverProxy.retrieve(). This is where the pieces connect:

  query text
    -> embed once (embed_fn)
    -> ChromaDB collection.query()           (the actual vector search)
    -> FrequencyTracker.record_query()       (remember what ranked highly)
    -> for each candidate: is_anomalous()?   (the poison decision)
    -> Quarantine.add() + emit critical event (if yes)
    -> return top-k CLEAN docs (quarantined docs replaced by next-best)

WHY IT EXISTS
-------------
The whole point of the module is that the agent must never receive a poisoned
document. If the agent called ChromaDB directly, nothing would stand between it
and the bait. This proxy is that stand-in: same API shape the agent expects,
but every result passes through detection first.

It also centralizes three side effects that must stay consistent:
  1. detector state updates (tracker + quarantine),
  2. event emission (delivery to the dashboard),
  3. state persistence (detector_state.json).
All three happen under one lock so a detection decision can never interleave
with another request or an admin reset.

Called from: main.py /retrieve, /admin/add-documents, /quarantine, /stats,
/admin/reset-detection routes. Calls: frequency_tracker.py, quarantine.py,
detector_state.py, events.py.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any

from .config import Config
from .detector_state import DetectorStateStore
from .events import EventContext, now_ms
from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine, QuarantinedDoc

POLICY_VERSION = "vector-anchor/1"


def _content_fingerprint(value: str) -> str:
    """SHA-256 hex digest of text. Used instead of raw text in event details:
    query text and document text may contain end-user secrets or credentials,
    and the ledger should never copy them (see the emit calls below)."""
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
        """Assembled by build_proxy() in main.py. Receives:
          collection:  the ChromaDB collection (store.py get_or_create_collection)
          embed_fn:    the embedding function (store.py build_embedding_function)
          tracker:     FrequencyTracker (loaded from disk or fresh)
          quarantine:  Quarantine (loaded from disk or fresh)
          cfg:         validated Config (config.py load_config)
          emit:        the EventEmitter (events.py make_emitter)
          state_store: atomic persistence for tracker + quarantine
        """
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

    def retrieve(
        self,
        query: str,
        k: int | None = None,
        ctx: EventContext | None = None,
    ) -> dict[str, Any]:
        """THE main flow. Called from main.py retrieve() for every /retrieve.

        Input:  query text, requested result count k, correlation context.
        Output: {query, results: [{id, document, distance}], withheld, quarantine_size}

        Step by step:
          1. n = k + candidate_buffer. Pull extra candidates so that if some
             results are quarantined, the next-best clean ones can fill their
             slots — the agent still gets k documents.
          2. Embed the query ONCE. The same vector goes to ChromaDB and to the
             frequency tracker, so the two decisions cannot diverge (using
             Chroma's query_texts would re-embed and could give different
             vectors with a non-deterministic embedder).
          3. collection.query(...) — the real vector search.
          4. Under the state lock:
             a. Record the top-ranked doc ids (ids[:top_rank_threshold]) in the
                tracker. A doc at rank 8 is NOT "ranking highly"; only the
                genuinely top results earn a hit.
             b. Walk every candidate in rank order:
                  - already quarantined? -> withheld, skip.
                  - tracker.is_anomalous(doc_id)? -> quarantine it NOW (first
                    time only emits the critical event), withhold it.
                  - else -> add to the clean list.
             c. served = clean[:k]; persist tracker+quarantine to disk.
          5. Emit an info "retrieval" event (query hashed, not copied).
          6. Return the clean results.

        Why withhold instead of returning nothing: the agent asked for k
        documents; silently returning fewer would break its retrieval
        contract. It gets k clean documents and a list of what was withheld and
        why.
        """
        # `ctx` carries the caller's correlation identity for this one
        # retrieval, so a quarantine here can be tied to detections the other
        # layers made in the same agent session.
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

            for doc_id, document, distance in zip(ids, docs, dists, strict=True):
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
                    # Emit the critical event only on FIRST quarantine (newly),
                    # so repeated retrievals of an already-quarantined doc do
                    # not flood the ledger.
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
            self._persist_state()

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
        """All quarantined docs, for the admin GET /quarantine route
        (main.py). The readable preview lives only here — never in events."""
        with self._state_lock:
            return self.quarantine.all()

    def quarantine_size(self) -> int:
        """How many docs are quarantined, for /stats."""
        with self._state_lock:
            return len(self.quarantine)

    def reset_detection(self) -> None:
        """Fresh tracker + quarantine, same corpus. Called from
        POST /admin/reset-detection (main.py); run_full_demo.sh uses it to
        re-run the poison attack from a clean slate."""
        with self._state_lock:
            self.tracker = FrequencyTracker(
                min_distinct_topics=self.cfg.min_distinct_topics,
                topic_similarity=self.cfg.topic_similarity,
                retention_horizon=self.cfg.retention_horizon,
                max_queries_per_doc=self.cfg.max_queries_per_doc,
            )
            self.quarantine = Quarantine()
            self._persist_state()

    def upsert_documents(self, documents: list[tuple[str, str]]) -> int:
        """Replace corpus documents and invalidate detector state atomically.

        Called from: main.py POST /admin/add-documents (and therefore from the
        seed/inject fixtures seed_corpus.py and inject_poison.py).

        Frequency and quarantine decisions describe specific content. Keeping
        them after an administrator replaces that content would either leave a
        remediated document blocked or immediately condemn the new version
        using the old version's history. So: upsert into ChromaDB, forget the
        tracker history for those ids, un-quarantine them, persist, and return
        the new corpus size.
        """
        ids = [doc_id for doc_id, _ in documents]
        with self._state_lock:
            self.collection.upsert(
                ids=ids,
                documents=[text for _, text in documents],
            )
            self.tracker.forget_documents(ids)
            self.quarantine.remove_many(ids)
            self._persist_state()
            return self.collection.count()

    def _persist_state(self) -> None:
        """Atomically save tracker + quarantine after every mutation, so the
        detector's memory survives restarts. The write happens inside the
        state lock; see detector_state.py for the atomic-temp-file mechanics."""
        if self.state_store:
            self.state_store.save(self.tracker, self.quarantine)
