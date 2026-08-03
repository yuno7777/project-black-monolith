"""Unit tests for the frequency-anomaly detector (pure Python, no ChromaDB).

Uses the same hashing embedder the service uses so query dissimilarity is
computed exactly as in production.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.embedding import HashingEmbeddingFunction  # noqa: E402
from src.frequency_tracker import FrequencyTracker  # noqa: E402

EF = HashingEmbeddingFunction(dim=256)


def emb(text: str):
    return EF([text])[0]


def make_tracker():
    return FrequencyTracker(
        min_distinct_topics=4,
        topic_similarity=0.30,
        retention_horizon=500,
        max_queries_per_doc=64,
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


def test_hits_older_than_the_horizon_stop_counting():
    """A hit beyond the retention horizon no longer contributes to the topic
    count. The horizon is now the detection reach — see test_evasion.py for
    what that costs an attacker who drips slower than it."""
    t = FrequencyTracker(
        min_distinct_topics=4,
        topic_similarity=0.30,
        retention_horizon=3,
        max_queries_per_doc=64,
    )
    topics = [
        "prune tomato garden",
        "red giant star galaxy",
        "boil pasta noodles",
        "emergency fund savings budget",
    ]
    for q in topics:
        t.record_query(["doc"], emb(q))
    # Only the last 3 queries are still within the horizon, so at most 3
    # distinct topics remain — never enough to flag.
    assert t.distinct_topic_count("doc") <= 3
    assert not t.is_anomalous("doc")


def test_expired_document_records_are_swept():
    """High-cardinality clean traffic must not leave one empty record per
    document forever. Pruning is lazy (on touch) with a periodic sweep, so
    drive enough queries to trigger one."""
    from src.frequency_tracker import SWEEP_INTERVAL

    t = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.30,
        retention_horizon=1,
        max_queries_per_doc=64,
    )
    t.record_query(["old-doc"], emb("garden soil"))
    for i in range(SWEEP_INTERVAL):
        t.record_query([f"filler-{i}"], emb(f"galaxy star cluster {i}"))

    assert "old-doc" not in t._docs


def test_replaced_documents_lose_old_frequency_history():
    t = make_tracker()
    for query in [
        "prune tomato garden",
        "red giant star galaxy",
        "boil pasta noodles",
        "emergency savings budget",
    ]:
        t.record_query(["replaced"], emb(query))
    assert t.is_anomalous("replaced")

    t.forget_documents(["replaced"])

    assert t.evaluate("replaced").total_queries == 0
    assert not t.is_anomalous("replaced")


def test_topic_score_is_independent_of_query_arrival_order():
    # The diagonal vector is similar to both axes, while the axes are
    # dissimilar to one another. Unsorted greedy clustering can score this as
    # either one or two topics depending on which vector arrives first.
    vectors = [[1.0, 0.0], [2**-0.5, 2**-0.5], [0.0, 1.0]]
    scores = []
    for order in [vectors, list(reversed(vectors)), [vectors[1], vectors[0], vectors[2]]]:
        tracker = FrequencyTracker(
            min_distinct_topics=2,
            topic_similarity=0.7,
            retention_horizon=500,
            max_queries_per_doc=64,
        )
        for vector in order:
            tracker.record_query(["doc"], vector)
        scores.append(tracker.distinct_topic_count("doc"))

    assert scores == [2, 2, 2]


@pytest.mark.parametrize("vector", [[], [float("nan")], [float("inf")]])
def test_invalid_embeddings_cannot_enter_detector_state(vector):
    tracker = make_tracker()
    with pytest.raises(ValueError, match="non-empty and finite"):
        tracker.record_query(["doc"], vector)
    assert tracker._docs == {}


def test_recorded_embeddings_are_not_mutated_by_the_caller():
    tracker = make_tracker()
    vector = [1.0, 0.0]
    tracker.record_query(["doc"], vector)
    vector[:] = [0.0, 1.0]

    assert tracker._docs["doc"].queries[0] == [1.0, 0.0]
