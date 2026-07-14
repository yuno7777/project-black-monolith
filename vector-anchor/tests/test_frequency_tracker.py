"""Unit tests for the frequency-anomaly detector (pure Python, no ChromaDB).

Uses the same hashing embedder the service uses so query dissimilarity is
computed exactly as in production.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.embedding import HashingEmbeddingFunction  # noqa: E402
from src.frequency_tracker import FrequencyTracker  # noqa: E402

EF = HashingEmbeddingFunction(dim=256)


def emb(text: str):
    return EF([text])[0]


def make_tracker():
    return FrequencyTracker(
        min_distinct_topics=4, topic_similarity=0.30, window_size=50
    )


def test_topic_specific_doc_is_not_flagged():
    """A document that only ever ranks for queries about ONE topic must never
    be flagged, no matter how often it is retrieved."""
    t = make_tracker()
    for _ in range(10):
        t.record_query(["garden-1"], emb("prune tomato plants garden soil water"))
    assert t.distinct_topic_count("garden-1") == 1
    assert not t.is_anomalous("garden-1")


def test_universal_bait_flagged_after_fourth_distinct_topic():
    """A document ranking across four DISSIMILAR queries crosses the
    threshold — and not before the fourth."""
    t = make_tracker()
    queries = [
        "prune tomato plants in the garden",
        "red giant star galaxy nebula",
        "boil pasta noodles simmer sauce",
        "emergency fund savings retirement budget",
    ]
    for i, q in enumerate(queries, start=1):
        t.record_query(["poison", f"topic-doc-{i}"], emb(q))
        if i < 4:
            assert not t.is_anomalous("poison"), f"flagged too early at topic {i}"
    assert t.is_anomalous("poison")
    assert t.evaluate("poison").distinct_topics == 4


def test_similar_queries_count_as_one_topic():
    """Rephrasings of the same question must not inflate the topic count."""
    t = make_tracker()
    for q in [
        "prune tomato plants in the garden",
        "how to prune tomato plants garden",
        "pruning tomato plants garden soil",
    ]:
        t.record_query(["doc"], emb(q))
    assert t.distinct_topic_count("doc") == 1


def test_rolling_window_evicts_old_queries():
    """Old queries fall out of the window and stop contributing to the
    topic count."""
    t = FrequencyTracker(min_distinct_topics=4, topic_similarity=0.30, window_size=3)
    topics = [
        "prune tomato garden",
        "red giant star galaxy",
        "boil pasta noodles",
        "emergency fund savings budget",
    ]
    for q in topics:
        t.record_query(["doc"], emb(q))
    # Window holds only the last 3 queries, so at most 3 distinct topics
    # remain — never enough to flag.
    assert t.distinct_topic_count("doc") <= 3
    assert not t.is_anomalous("doc")
