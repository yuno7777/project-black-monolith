import pytest

from src.embedding import HashingEmbeddingFunction
from src.frequency_tracker import FrequencyTracker
from src.quarantine import Quarantine, QuarantinedDoc


def test_tracker_snapshot_round_trip_preserves_detector_state():
    embed = HashingEmbeddingFunction(dim=32)
    tracker = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.2,
        window_size=5,
    )
    tracker.record_query(["doc"], embed(["garden soil"])[0])
    tracker.record_query(["doc"], embed(["galaxy star"])[0])

    restored = FrequencyTracker.from_snapshot(
        tracker.snapshot(),
        min_distinct_topics=2,
        topic_similarity=0.2,
        window_size=5,
    )

    assert restored.evaluate("doc") == tracker.evaluate("doc")
    assert restored.snapshot() == tracker.snapshot()


def test_tracker_rejects_state_outside_the_current_window():
    tracker = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.2,
        window_size=2,
    )
    tracker.record_query(["doc"], [1.0])
    state = tracker.snapshot()
    state["documents"]["doc"]["99"] = [1.0]

    with pytest.raises(ValueError, match="embedding"):
        FrequencyTracker.from_snapshot(
            state,
            min_distinct_topics=2,
            topic_similarity=0.2,
            window_size=2,
        )


def test_quarantine_snapshot_round_trip_and_duplicate_rejection():
    quarantine = Quarantine()
    quarantine.add(
        QuarantinedDoc(
            doc_id="doc-1",
            reason="frequency_anomaly",
            score=4,
            preview="safe preview",
            quarantined_at_ms=100,
        )
    )
    snapshot = quarantine.snapshot()

    restored = Quarantine.from_snapshot(snapshot)
    assert restored.is_quarantined("doc-1")
    with pytest.raises(ValueError, match="duplicate"):
        Quarantine.from_snapshot(snapshot + snapshot)
