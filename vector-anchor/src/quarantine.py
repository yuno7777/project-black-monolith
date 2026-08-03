"""Quarantine store for documents flagged as corpus poison."""

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

    def remove_many(self, doc_ids: list[str]) -> None:
        for doc_id in doc_ids:
            self._docs.pop(doc_id, None)

    def __len__(self) -> int:
        return len(self._docs)

    def snapshot(self) -> list[dict]:
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
    def from_snapshot(cls, data: list[dict]) -> "Quarantine":
        if not isinstance(data, list) or len(data) > 100_000:
            raise ValueError("invalid quarantine state")
        quarantine = cls()
        for raw in data:
            if not isinstance(raw, dict):
                raise ValueError("invalid quarantine entry")
            doc = QuarantinedDoc(
                doc_id=raw.get("doc_id"),
                reason=raw.get("reason"),
                score=raw.get("score"),
                preview=raw.get("preview"),
                quarantined_at_ms=raw.get("quarantined_at_ms"),
            )
            if (
                not isinstance(doc.doc_id, str)
                or not 1 <= len(doc.doc_id) <= 128
                or not isinstance(doc.reason, str)
                or not 1 <= len(doc.reason) <= 128
                or isinstance(doc.score, bool)
                or not isinstance(doc.score, int)
                or doc.score < 0
                or not isinstance(doc.preview, str)
                or len(doc.preview) > 160
                or isinstance(doc.quarantined_at_ms, bool)
                or not isinstance(doc.quarantined_at_ms, int)
                or doc.quarantined_at_ms < 0
            ):
                raise ValueError("invalid quarantine entry fields")
            if not quarantine.add(doc):
                raise ValueError("duplicate quarantine entry")
        return quarantine
