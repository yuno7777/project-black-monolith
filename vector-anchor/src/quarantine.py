"""Quarantine store for documents flagged as corpus poison.

WHAT THIS FILE IS
-----------------
A simple in-memory list of documents that VectorAnchor has decided are poison.
Once a document is quarantined here, retriever_proxy.py withholds it from every
future retrieval — the agent never sees it again, no matter how well it ranks.

WHY IT EXISTS
-------------
The FrequencyTracker decides a document is suspicious; this store remembers
the verdict. The two are separate so that (a) the verdict is not re-derived on
every request, and (b) the quarantine can carry extra human-readable info (the
reason and a short preview of the text) that has nothing to do with the
scoring math.

Interaction with the rest of the module:
  - retriever_proxy.py: is_quarantined() checked per candidate; add() called
    on first detection; remove_many() on document upsert; all() for the admin
    /quarantine route.
  - detector_state.py: snapshot()/from_snapshot() persist it across restarts.
  - main.py: constructs the (initially empty) store.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class QuarantinedDoc:
    """One quarantined document.

    preview: the first 160 chars of the document text. Note this readable text
    lives ONLY here (and in the admin /quarantine endpoint). It is deliberately
    never put into event telemetry — event details carry a SHA-256 of the text
    instead (see retriever_proxy.py).
    """

    doc_id: str
    reason: str
    score: int
    preview: str
    quarantined_at_ms: int


@dataclass
class Quarantine:
    _docs: dict[str, QuarantinedDoc] = field(default_factory=dict)

    def is_quarantined(self, doc_id: str) -> bool:
        """Is this document already blocked? Called by retriever_proxy.py for
        every candidate document of every /retrieve."""
        return doc_id in self._docs

    def add(self, doc: QuarantinedDoc) -> bool:
        """Add a document. Returns True if newly quarantined, False if it was
        already quarantined.

        The return value matters: retriever_proxy.py only emits the critical
        `corpus_poison_quarantine` event when add() returns True, so repeated
        retrievals of an already-quarantined document do not flood the ledger.
        """
        if doc.doc_id in self._docs:
            return False
        self._docs[doc.doc_id] = doc
        return True

    def all(self) -> list[QuarantinedDoc]:
        """All quarantined docs — served by the admin GET /quarantine route
        (main.py) and used by the demo script's final check."""
        return list(self._docs.values())

    def remove_many(self, doc_ids: list[str]) -> None:
        """Un-quarantine documents whose corpus content was replaced. Called
        by retriever_proxy.py upsert_documents(): a remediated document must
        not stay blocked."""
        for doc_id in doc_ids:
            self._docs.pop(doc_id, None)

    def __len__(self) -> int:
        return len(self._docs)

    def snapshot(self) -> list[dict]:
        """Serialize for detector_state.py (atomic write after each change)."""
        return [
            {
                "doc_id": doc.doc_id,
                "reason": doc.reason,
                "score": doc.score,
                "preview": doc.preview,
                "quarantined_at_ms": doc.quarantined_at_ms,
            }
            for doc in self._docs.values()
        ]

    @classmethod
    def from_snapshot(cls, data: list[dict]) -> Quarantine:
        """Rebuild from saved state. Called by detector_state.py load() at
        startup. Validation is strict because the file on disk is untrusted
        input (and an over-large or malformed state must fail load() loudly so
        main.py can set the file aside and start fresh)."""
        if not isinstance(data, list) or len(data) > 100_000:
            raise ValueError("invalid quarantine state")
        quarantine = cls()
        for raw in data:
            if not isinstance(raw, dict):
                raise ValueError("invalid quarantine entry")
            doc_id = raw.get("doc_id")
            reason = raw.get("reason")
            score = raw.get("score")
            preview = raw.get("preview")
            quarantined_at_ms = raw.get("quarantined_at_ms")
            if (
                not isinstance(doc_id, str)
                or not 1 <= len(doc_id) <= 128
                or not isinstance(reason, str)
                or not 1 <= len(reason) <= 128
                or isinstance(score, bool)
                or not isinstance(score, int)
                or score < 0
                or not isinstance(preview, str)
                or len(preview) > 160
                or isinstance(quarantined_at_ms, bool)
                or not isinstance(quarantined_at_ms, int)
                or quarantined_at_ms < 0
            ):
                raise ValueError("invalid quarantine entry fields")
            doc = QuarantinedDoc(
                doc_id=doc_id,
                reason=reason,
                score=score,
                preview=preview,
                quarantined_at_ms=quarantined_at_ms,
            )
            if not quarantine.add(doc):
                raise ValueError("duplicate quarantine entry")
        return quarantine
