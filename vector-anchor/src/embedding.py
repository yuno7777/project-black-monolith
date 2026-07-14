"""Embedding functions for VectorAnchor.

Default is a lightweight, dependency-free, DETERMINISTIC hashing embedder
(bag-of-words hashed into a fixed-dimension L2-normalized vector). It is
chosen so the corpus-poisoning demo runs fully offline with no model download
and produces reproducible rankings: cosine similarity under this scheme
tracks shared vocabulary, which is exactly what makes an engineered
"universal bait" document (stuffed with terms from many topics) rank highly
across unrelated queries.

Set MONOLITH_EMBEDDING=default to instead use ChromaDB's built-in
sentence-transformers embedder for real semantic quality (heavier; downloads
a model on first use).
"""

from __future__ import annotations

import hashlib
import re

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Common English stopwords are dropped before hashing. They carry no topic
# signal, and leaving them in creates spurious similarity between otherwise
# unrelated queries (e.g. two questions that merely share "how should I"),
# which would wrongly merge distinct topics in the frequency tracker.
_STOPWORDS = frozenset(
    """
    a an and are as at be by for from how i in into is it its my of on or over
    should so than that the their them then there these this to until up was
    what when where which who will with you your do does did much many long
    """.split()
)


class HashingEmbeddingFunction:
    """ChromaDB-compatible embedding function (callable taking a list of
    documents and returning a list of float vectors)."""

    # Chroma >=0.4.16 requires embedding functions to be named for
    # (de)serialization of a collection's configuration.
    @staticmethod
    def name() -> str:
        return "monolith-hashing"

    def __init__(self, dim: int = 256):
        self.dim = dim

    def __call__(self, input: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in input]

    # ChromaDB >=1.x invokes these explicitly (documents vs. queries can be
    # embedded differently by some models; for a bag-of-words embedder they
    # are identical). Defined as plain delegating methods so this class needs
    # no chromadb import and stays unit-testable on its own.
    def embed_documents(self, input: list[str]) -> list[list[float]]:
        return self.__call__(input)

    def embed_query(self, input: list[str]) -> list[list[float]]:
        return self.__call__(input)

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in _TOKEN_RE.findall(text.lower()):
            if token in _STOPWORDS:
                continue
            # Stable per-token bucket + sign from a hash of the token.
            digest = hashlib.md5(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[bucket] += sign
        norm = sum(v * v for v in vec) ** 0.5
        if norm > 0.0:
            vec = [v / norm for v in vec]
        return vec


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors (0.0 if either is zero)."""
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
