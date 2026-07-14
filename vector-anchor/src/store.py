"""ChromaDB collection helpers shared by the seed scripts and the service, so
they always open the collection with the same embedding function."""

from __future__ import annotations

from .config import Config
from .embedding import HashingEmbeddingFunction


def build_embedding_function(cfg: Config):
    """Return a concrete, callable ChromaDB embedding function. We always
    return an explicit object (never None) so the service can also reuse it
    to embed live queries for the frequency tracker."""
    if cfg.embedding == "default":
        # Real semantic embeddings; downloads a model on first use.
        from chromadb.utils import embedding_functions

        return embedding_functions.DefaultEmbeddingFunction()
    return HashingEmbeddingFunction(dim=cfg.embedding_dim)


def get_client(cfg: Config):
    import chromadb

    return chromadb.PersistentClient(path=cfg.chroma_path)


def get_or_create_collection(cfg: Config, embedding_function=None):
    client = get_client(cfg)
    ef = embedding_function or build_embedding_function(cfg)
    return client.get_or_create_collection(
        name=cfg.collection_name,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )
