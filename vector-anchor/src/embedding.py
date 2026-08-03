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
import math
import re

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Common English stopwords are dropped before hashing. They carry no topic
# signal, and leaving them in creates spurious similarity between otherwise
# unrelated queries (e.g. two questions that merely share "how should I"),
# which would wrongly merge distinct topics in the frequency tracker.
_STOPWORDS = frozenset(
    ["a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "how", "i", "in", "into", "is", "it", "its", "my", "of", "on", "or", "over", "should", "so", "than", "that", "the", "their", "them", "then", "there", "these", "this", "to", "until", "up", "was", "what", "when", "where", "which", "who", "will", "with", "you", "your", "do", "does", "did", "much", "many", "long"]
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


def normalize(vec: list[float]) -> list[float]:
    """Scale a vector to unit length (a zero vector is returned unchanged).

    Cosine similarity is scale-invariant, so normalizing once on the way into
    the detector lets every later comparison be a plain dot product instead of
    recomputing both norms per call. See ``unit_dot``.
    """
    norm = sum(value * value for value in vec) ** 0.5
    if norm == 0.0:
        return list(vec)
    return [value / norm for value in vec]


def unit_dot(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two vectors already normalized by ``normalize``.

    Deliberately unvalidated and equal-length by construction: this runs on the
    detector's hot path, once per retained hit per retrieval, and its inputs
    have already been validated at the boundary they entered through
    (``record_query`` or ``from_snapshot``). Measured, the validating ``cosine``
    below costs about 4x as much per call — three extra passes over the vectors
    to re-check finiteness and recompute two norms that do not change.
    """
    return sum(x * y for x, y in zip(a, b))


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors (0.0 if either is zero)."""
    if not a or len(a) != len(b):
        raise ValueError("embedding vectors must be non-empty and have equal dimensions")
    if not all(math.isfinite(value) for value in (*a, *b)):
        raise ValueError("embedding vectors must contain only finite values")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
