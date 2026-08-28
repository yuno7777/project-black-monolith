"""Embedding functions for VectorAnchor.

WHAT THIS FILE IS
-----------------
Vector math helpers: the default embedder, plus the similarity primitives the
FrequencyTracker uses. It is deliberately dependency-free (no chromadb, no
torch, no sentence-transformers import at module load) so the detector logic
can be unit-tested without any heavy installs.

THE DEFAULT EMBEDDER (simple version)
-------------------------------------
Text goes in, a list of 256 numbers comes out. The trick: each word is hashed
to a fixed "bucket" with a sign, so two texts that share vocabulary get
similar vectors. That is exactly the property the poison detector relies on:
a "universal bait" document stuffed with gardening words, astronomy words,
cooking words and finance words will be similar to queries from ALL four
topics — which is what makes it rank for all of them and then get caught.

WHY "HASH" BY DEFAULT
---------------------
Reproducibility. A real semantic embedder (sentence-transformers) downloads a
model and its rankings are model-version-dependent; the demo and the CI gates
need identical behavior on every run. The hashing embedder is deterministic and
offline. Set MONOLITH_EMBEDDING=default to swap in Chroma's built-in embedder
for real semantic quality.

The performance-relevant bit: vectors are normalized ONCE (normalize) when they
enter the detector, so every later similarity check is a plain dot product
(unit_dot) instead of a full cosine (which re-validates 512 floats and
recomputes both norms — measured ~4x slower on the detector's hottest path).
"""

from __future__ import annotations

import hashlib
import math
import re

# Match runs of letters/digits (lowercased later). This is a bag-of-words
# tokenizer: "gardening," -> "gardening". No stemming, no word embeddings.
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
    documents and returning a list of float vectors).

    This is the DEFAULT embedder. ChromaDB calls it when documents are added
    and when queries are embedded — and retriever_proxy.py also calls it
    directly so the detector sees the exact same vector Chroma uses.

    How _embed works, step by step:
      1. Lowercase the text, find all word tokens.
      2. Skip stopwords.
      3. For each token: MD5 the token, use the first 4 bytes to pick a
         dimension ("bucket") and bit 4 to pick +1 or -1. Add that to the
         bucket. (Signed hashing: words cancel less than unsigned counting,
         giving more distinguishable vectors.)
      4. L2-normalize the result so cosine similarity = dot product.

    Chroma >=0.4.16 requires a .name() so the collection config can be
    (de)serialized; ChromaDB >=1.x also calls embed_documents/embed_query
    explicitly. For a bag-of-words embedder all three are identical.
    """

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

    Called from: frequency_tracker.py (record_query, from_snapshot) and tests.
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

    Called from: frequency_tracker.py (_evict_for, distinct_topic_count).
    """
    return sum(x * y for x, y in zip(a, b))


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors (0.0 if either is zero).

    The SAFE, validating version. Used by tests and calibration fixtures where
    correctness matters more than speed; the detector hot path uses unit_dot.
    """
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
