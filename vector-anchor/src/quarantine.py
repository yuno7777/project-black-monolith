"""Quarantine store for documents flagged as corpus poison.

Once a document is quarantined it is withheld from all future retrieval
results; the retriever serves the next-best clean document in its place. The
quarantine is in-memory (single-operator local demo system); restart clears
it and detection re-learns from the live stream.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class QuarantinedDoc:
    doc_id: str
    reason: str
    score: int
    preview: str
    quarantined_at_ms: int


@dataclass
class Quarantine:
    _docs: dict[str, QuarantinedDoc] = field(default_factory=dict)

    def is_quarantined(self, doc_id: str) -> bool:
        return doc_id in self._docs

    def add(self, doc: QuarantinedDoc) -> bool:
        """Add a document. Returns True if newly quarantined, False if it was
        already quarantined."""
        if doc.doc_id in self._docs:
            return False
        self._docs[doc.doc_id] = doc
        return True

    def all(self) -> list[QuarantinedDoc]:
        return list(self._docs.values())

    def __len__(self) -> int:
        return len(self._docs)
