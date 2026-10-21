"""The detector-reset path, tested on the module's own side of the wire.

``POST /admin/reset-detection`` is the one administrative action that erases
evidence. It clears the frequency history and the quarantine so the next
attack starts from a clean slate, and the dashboard's onboarding page can
call it — which means anyone who can authenticate to the dashboard as an
administrator can reach it.

Nothing about it was tested, on either side of the wire. These tests hold
the module's half of that contract:

* the route refuses a caller without the configured bearer, and refuses
  outright when no bearer is configured — an unconfigured administrative
  credential must not become an open door;
* the reset clears the history and the quarantine and leaves the corpus
  alone: it is a *detector* reset, not a wipe;
* the detector that comes back is the one that was configured — a reset must
  not silently re-tune the thresholds;
* the cleared state reaches the disk immediately, so a restart cannot
  resurrect the history the operator asked to erase.

That last one is why the reset forces a flush. A reset that only marked the
state dirty would be undone by the next periodic write, which would put back
exactly the history that was just cleared.

The dashboard's half of the same contract lives in
``dashboard/test/reset-detection.test.ts``.
"""

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from src.config import load_config
from src.detector_state import DetectorStateStore
from src.events import EventContext
from src.frequency_tracker import FrequencyTracker
from src.main import app, reset_detection
from src.quarantine import Quarantine, QuarantinedDoc
from src.retriever_proxy import RetrieverProxy

ADMIN_TOKEN = "reset-detection-admin-0000"
BAIT_ID = "bait-universal-answer"
CLEAN_ID = "doc-specific-answer"

# Four mutually dissimilar directions. At the shipped topic similarity of
# 0.20 each of these is a topic of its own, so four of them is exactly the
# bait threshold.
DISSIMILAR = [[1.0, 0.0], [0.0, 1.0], [-1.0, 0.0], [0.0, -1.0]]

BAIT_TEXT = "notes about soil composition in raised beds"
CLEAN_TEXT = "the tutoring timetable for the reading group"


def request(authorization: str = "") -> Request:
    headers = []
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    return Request({"type": "http", "headers": headers, "query_string": b""})


class Collection:
    """The corpus, standing in for the ChromaDB client."""

    def __init__(self) -> None:
        self.documents = {BAIT_ID: BAIT_TEXT, CLEAN_ID: CLEAN_TEXT}

    def count(self) -> int:
        return len(self.documents)

    def query(self, **_kwargs):
        ids = list(self.documents)
        return {
            "ids": [ids],
            "documents": [[self.documents[doc_id] for doc_id in ids]],
            "distances": [[0.1 for _ in ids]],
        }

    def delete_collection(self) -> None:
        """ChromaDB's collection has this; a reset must not call it."""
        self.documents = {}


def make_config(monkeypatch, tmp_path, **overrides):
    """The shipped configuration, with only the knobs a test cares about moved."""
    values: dict[str, str | None] = {
        "MONOLITH_ADMIN_TOKEN": ADMIN_TOKEN,
        "MONOLITH_MIN_DISTINCT_TOPICS": "4",
        "MONOLITH_TOPIC_SIMILARITY": "0.20",
        "MONOLITH_RETENTION_HORIZON": "500",
        "MONOLITH_MAX_QUERIES_PER_DOC": "8",
        "MONOLITH_MAX_TRACKED_DOCS": "4321",
        "MONOLITH_DETECTOR_STATE_PATH": str(tmp_path / "detector_state.json"),
        # A long flush interval, so that a state write only happens when
        # something forces it. That is what gives the "the reset reaches the
        # disk" test its meaning: without the forced flush the file would
        # still hold the bait's history.
        "MONOLITH_STATE_FLUSH_INTERVAL_MS": "600000",
    }
    values.update(overrides)
    for key, value in values.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    return load_config()


def make_proxy(monkeypatch, tmp_path, **cfg_overrides):
    cfg = make_config(monkeypatch, tmp_path, **cfg_overrides)
    tracker = FrequencyTracker(
        min_distinct_topics=cfg.min_distinct_topics,
        topic_similarity=cfg.topic_similarity,
        retention_horizon=cfg.retention_horizon,
        max_queries_per_doc=cfg.max_queries_per_doc,
        max_tracked_docs=cfg.max_tracked_docs,
    )
    store = DetectorStateStore(
        cfg.detector_state_path,
        min_distinct_topics=cfg.min_distinct_topics,
        topic_similarity=cfg.topic_similarity,
        retention_horizon=cfg.retention_horizon,
        max_queries_per_doc=cfg.max_queries_per_doc,
        max_tracked_docs=cfg.max_tracked_docs,
    )
    collection = Collection()
    proxy = RetrieverProxy(
        collection=collection,
        embed_fn=lambda _queries: [[1.0, 0.0]],
        tracker=tracker,
        quarantine=Quarantine(),
        cfg=cfg,
        emit=lambda *_args, **_kwargs: None,
        state_store=store,
    )
    app.state.proxy = proxy
    return proxy, collection, store


def seed_bait(proxy) -> None:
    """Give the bait a history that has already crossed the threshold."""
    for vector in DISSIMILAR:
        proxy.tracker.record_query([BAIT_ID], vector)
    assert proxy.tracker.distinct_topic_count(BAIT_ID) == 4
    proxy.tracker.is_anomalous(BAIT_ID)
    proxy.quarantine.add(
        QuarantinedDoc(
            doc_id=BAIT_ID,
            reason="universal_bait_frequency_anomaly",
            score=4,
            preview=BAIT_TEXT,
            quarantined_at_ms=1_700_000_000_000,
        )
    )


def test_the_reset_route_refuses_a_caller_without_the_bearer(monkeypatch, tmp_path):
    proxy, _collection, _store = make_proxy(monkeypatch, tmp_path)
    seed_bait(proxy)

    with pytest.raises(HTTPException) as refused:
        reset_detection(request("Bearer not-the-admin-token-000"))

    assert refused.value.status_code == 401
    # A refused reset changes nothing: the bait is still quarantined and its
    # history is intact.
    assert proxy.quarantine.is_quarantined(BAIT_ID)
    assert proxy.tracker.distinct_topic_count(BAIT_ID) == 4


def test_the_reset_route_refuses_itself_when_no_credential_is_configured(
    monkeypatch, tmp_path
):
    proxy, _collection, _store = make_proxy(
        monkeypatch, tmp_path, MONOLITH_ADMIN_TOKEN=None
    )
    seed_bait(proxy)

    with pytest.raises(HTTPException) as unavailable:
        reset_detection(request("Bearer " + ADMIN_TOKEN))

    assert unavailable.value.status_code == 503
    assert proxy.quarantine.is_quarantined(BAIT_ID)
    assert proxy.tracker.distinct_topic_count(BAIT_ID) == 4


def test_the_reset_clears_the_history_and_the_quarantine(monkeypatch, tmp_path):
    proxy, _collection, _store = make_proxy(monkeypatch, tmp_path)
    seed_bait(proxy)

    result = reset_detection(request("Bearer " + ADMIN_TOKEN))

    # The shape the dashboard reads.
    assert result == {"status": "reset"}
    assert proxy.tracker.distinct_topic_count(BAIT_ID) == 0
    assert proxy.quarantine.list_ids() == []
    assert not proxy.quarantine.is_quarantined(BAIT_ID)


def test_the_reset_leaves_the_corpus_alone(monkeypatch, tmp_path):
    proxy, collection, _store = make_proxy(monkeypatch, tmp_path)
    seed_bait(proxy)
    before = dict(collection.documents)

    reset_detection(request("Bearer " + ADMIN_TOKEN))

    # It is a *detector* reset: the documents are still there to be detected
    # again.
    assert collection.documents == before
    assert collection.count() == len(before)


def test_the_reset_keeps_the_configured_thresholds(monkeypatch, tmp_path):
    proxy, _collection, _store = make_proxy(monkeypatch, tmp_path)
    cfg = proxy.cfg

    reset_detection(request("Bearer " + ADMIN_TOKEN))

    tracker = proxy.tracker
    assert tracker.min_distinct_topics == cfg.min_distinct_topics
    assert tracker.topic_similarity == cfg.topic_similarity
    assert tracker.retention_horizon == cfg.retention_horizon
    assert tracker.max_queries_per_doc == cfg.max_queries_per_doc
    assert tracker.max_tracked_docs == cfg.max_tracked_docs


def test_the_reset_reaches_the_disk_immediately(monkeypatch, tmp_path):
    proxy, _collection, store = make_proxy(monkeypatch, tmp_path)
    seed_bait(proxy)
    # The bait's history is on disk, as it would be after a periodic flush.
    # The flush also starts the interval, so a write that is not forced is
    # skipped for the whole of it — which is what makes this test able to
    # tell a forced write from an ordinary one.
    assert proxy.flush_state() is True
    assert BAIT_ID in store.load()[0].snapshot()["documents"]

    reset_detection(request("Bearer " + ADMIN_TOKEN))

    # A new store at the same path is what a restarted process gets. It must
    # not bring the history back: the reset forced the write, and a reset
    # that only marked the state dirty would be undone by the next flush.
    restarted = DetectorStateStore(
        store.path,
        min_distinct_topics=store.min_distinct_topics,
        topic_similarity=store.topic_similarity,
        retention_horizon=store.retention_horizon,
        max_queries_per_doc=store.max_queries_per_doc,
        max_tracked_docs=store.max_tracked_docs,
    )
    tracker, quarantine = restarted.load()
    assert tracker.distinct_topic_count(BAIT_ID) == 0
    assert quarantine.list_ids() == []


def test_the_detector_counts_from_scratch_after_a_reset(monkeypatch, tmp_path):
    proxy, _collection, _store = make_proxy(monkeypatch, tmp_path)
    seed_bait(proxy)
    assert proxy.tracker.is_anomalous(BAIT_ID) is True

    reset_detection(request("Bearer " + ADMIN_TOKEN))

    assert proxy.tracker.distinct_topic_count(BAIT_ID) == 0
    assert proxy.tracker.is_anomalous(BAIT_ID) is False


def test_a_quarantined_bait_is_served_again_after_a_reset(monkeypatch, tmp_path):
    proxy, _collection, _store = make_proxy(monkeypatch, tmp_path)
    seed_bait(proxy)
    ctx = EventContext(session_id="session-reset-test")

    withheld = proxy.retrieve("anything at all", ctx=ctx)
    assert [item["id"] for item in withheld["results"]] == [CLEAN_ID]
    assert withheld["withheld"], "the quarantined bait should have been withheld"

    reset_detection(request("Bearer " + ADMIN_TOKEN))

    served = proxy.retrieve("anything at all", ctx=ctx)
    assert [item["id"] for item in served["results"]] == [BAIT_ID, CLEAN_ID]
    assert served["withheld"] == []
