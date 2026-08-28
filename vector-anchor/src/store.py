"""ChromaDB collection helpers shared by the seed scripts and the service, so
they always open the collection with the same embedding function.

WHAT THIS FILE IS
-----------------
The only file that touches the ChromaDB client. Everything else (the service,
the seed fixture, the poison fixture) gets its collection from here, which
guarantees they all talk to the same collection with the same embedding
function.

WHY ONE CLIENT MATTERS
----------------------
ChromaDB's PersistentClient stores its data in a local SQLite database. Two
clients opening the same path from the same process contend on that SQLite
store and can corrupt each other's view. That is why the fixtures do NOT open
their own client — they POST to /admin/add-documents instead, and the service's
single client (stored on the RetrieverProxy) does the write.

Called from:
  - main.py build_proxy()        (get_or_create_collection for the service)
  - fixtures/seed_corpus.py and fixtures/inject_poison.py
                                 (same helpers, so fixtures match the service)
"""

from __future__ import annotations

from .config import Config
from .embedding import HashingEmbeddingFunction


def build_embedding_function(cfg: Config):
    """Return a concrete, callable ChromaDB embedding function. We always
    return an explicit object (never None) so the service can also reuse it
    to embed live queries for the frequency tracker.

    - "hash" (default): HashingEmbeddingFunction — deterministic, offline.
    - "default": ChromaDB's built-in sentence-transformers embedder — real
      semantic quality, downloads a model on first use.
    """
    if cfg.embedding == "default":
        # Real semantic embeddings; downloads a model on first use.
        from chromadb.utils import embedding_functions

        return embedding_functions.DefaultEmbeddingFunction()
    return HashingEmbeddingFunction(dim=cfg.embedding_dim)


def get_client(cfg: Config):
    """Open the PersistentClient rooted at cfg.chroma_path (a Docker volume in
    the compose stack, so the corpus survives restarts)."""
    import chromadb

    return chromadb.PersistentClient(path=cfg.chroma_path)


def get_or_create_collection(cfg: Config, embedding_function=None):
    """Open (or create) the named collection with the given embedding function
    and cosine distance space.

    `metadata={"hnsw:space": "cosine"}` tells ChromaDB's HNSW index to rank by
    cosine similarity, matching how the detector compares query vectors.
    """
    client = get_client(cfg)
    ef = embedding_function or build_embedding_function(cfg)
    return client.get_or_create_collection(
        name=cfg.collection_name,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )
