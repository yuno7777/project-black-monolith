import pathlib

import pytest

from src.embedding import HashingEmbeddingFunction
from src.detector_state import DetectorStateStore
from src.frequency_tracker import FrequencyTracker
from src.quarantine import Quarantine, QuarantinedDoc


def test_tracker_snapshot_round_trip_preserves_detector_state():
    embed = HashingEmbeddingFunction(dim=32)
    tracker = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )
    tracker.record_query(["doc"], embed(["garden soil"])[0])
    tracker.record_query(["doc"], embed(["galaxy star"])[0])

    restored = FrequencyTracker.from_snapshot(
        tracker.snapshot(),
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )

    assert restored.evaluate("doc") == tracker.evaluate("doc")
    assert restored.snapshot() == tracker.snapshot()


def test_tracker_rejects_state_referring_to_queries_that_never_happened():
    tracker = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )
    tracker.record_query(["doc"], [1.0])
    state = tracker.snapshot()
    # A query id at or beyond the next id cannot have been recorded.
    state["documents"]["doc"]["99"] = [1.0]

    with pytest.raises(ValueError, match="embedding"):
        FrequencyTracker.from_snapshot(
            state,
            min_distinct_topics=2,
            topic_similarity=0.2,
            retention_horizon=500,
        max_queries_per_doc=64,
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


def test_detector_state_store_persists_tracker_and_quarantine_atomically(tmp_path):
    store = DetectorStateStore(
        str(tmp_path / "detector.json"),
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )
    tracker = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )
    tracker.record_query(["doc"], [1.0, 0.0])
    quarantine = Quarantine()
    quarantine.add(
        QuarantinedDoc("doc", "frequency_anomaly", 2, "preview", 100)
    )

    store.save(tracker, quarantine)
    restored_tracker, restored_quarantine = store.load()

    assert restored_tracker.snapshot() == tracker.snapshot()
    assert restored_quarantine.is_quarantined("doc")
    assert not (tmp_path / "detector.json.tmp").exists()


def test_detector_state_policy_changes_require_an_explicit_reset(tmp_path):
    path = str(tmp_path / "detector.json")
    original = DetectorStateStore(
        path,
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )
    original.save(
        FrequencyTracker(
            min_distinct_topics=2,
            topic_similarity=0.2,
            retention_horizon=500,
        max_queries_per_doc=64,
        ),
        Quarantine(),
    )
    changed = DetectorStateStore(
        path,
        min_distinct_topics=3,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )

    with pytest.raises(ValueError, match="different policy"):
        changed.load()


def test_version_one_state_is_refused_rather_than_reinterpreted():
    """v1 held a global query window whose semantics no longer exist. Loading
    it under per-document retention would produce scores nobody can reproduce,
    so it is refused outright."""
    legacy = {
        "version": 1,
        "next_query_id": 2,
        "window": [0, 1],
        "documents": {"doc": {"0": [1.0], "1": [0.0, 1.0]}},
    }
    with pytest.raises(ValueError, match="unsupported frequency tracker state"):
        FrequencyTracker.from_snapshot(
            legacy,
            min_distinct_topics=2,
            topic_similarity=0.2,
            retention_horizon=500,
            max_queries_per_doc=64,
        )


def test_unreadable_state_is_set_aside_not_deleted(tmp_path):
    """An upgrade must not crash-loop the service, and must not destroy the
    record of what the detector had seen."""
    path = tmp_path / "detector.json"
    store = DetectorStateStore(
        str(path),
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=64,
    )
    path.write_text('{"version": 1, "stale": true}', encoding="utf-8")

    with pytest.raises(ValueError):
        store.load()
    moved = store.quarantine_unreadable()

    assert not path.exists()
    assert "stale" in pathlib.Path(moved).read_text(encoding="utf-8")
