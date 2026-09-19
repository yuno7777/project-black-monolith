"""Detector state transitions are serialized across FastAPI worker threads."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from src.quarantine import Quarantine
from src.retriever_proxy import RetrieverProxy


class Collection:
    def __init__(self):
        self.documents = {"doc": "document"}

    def query(self, **_kwargs):
        return {
            "ids": [["doc"]],
            "documents": [["document"]],
            "distances": [[0.1]],
        }

    def upsert(self, *, ids, documents):
        self.documents.update(zip(ids, documents))

    def count(self):
        return len(self.documents)


class RacyTracker:
    def __init__(self):
        self.active = 0
        self.max_active = 0

    def record_query(self, _ids, _embedding):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        time.sleep(0.01)
        self.active -= 1

    def is_anomalous(self, _doc_id):
        return False

    def forget_documents(self, _doc_ids):
        pass


def test_concurrent_retrievals_do_not_interleave_detector_updates():
    tracker = RacyTracker()
    proxy = RetrieverProxy(
        collection=Collection(),
        embed_fn=lambda _queries: [[1.0]],
        tracker=tracker,
        quarantine=Quarantine(),
        cfg=SimpleNamespace(
            top_k=1,
            candidate_buffer=0,
            top_rank_threshold=1,
            min_distinct_topics=4,
            topic_similarity=0.2,
            window_size=50,
        ),
        emit=lambda *_args, **_kwargs: None,
    )
    barrier = threading.Barrier(8)

    def retrieve(index):
        barrier.wait()
        return proxy.retrieve(f"query-{index}")

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(retrieve, range(8)))

    assert len(results) == 8
    assert tracker.max_active == 1


def test_upsert_clears_stale_quarantine_and_tracker_state():
    collection = Collection()
    tracker = RacyTracker()
    forgotten = []
    tracker.forget_documents = lambda ids: forgotten.extend(ids)
    quarantine = Quarantine()
    from src.quarantine import QuarantinedDoc

    quarantine.add(QuarantinedDoc("doc", "old-content", 4, "old", 1))
    proxy = RetrieverProxy(
        collection=collection,
        embed_fn=lambda _queries: [[1.0]],
        tracker=tracker,
        quarantine=quarantine,
        cfg=SimpleNamespace(),
        emit=lambda *_args, **_kwargs: None,
    )

    total = proxy.upsert_documents([("doc", "replacement")])

    assert total == 1
    assert collection.documents["doc"] == "replacement"
    assert forgotten == ["doc"]
    assert not quarantine.is_quarantined("doc")


def test_corpus_update_waits_for_inflight_query_and_clears_its_history():
    entered = threading.Event()
    release = threading.Event()
    updated = threading.Event()
    history = []

    class PausedCollection(Collection):
        def query(self, **kwargs):
            entered.set()
            assert release.wait(3)
            return super().query(**kwargs)

    tracker = RacyTracker()
    tracker.record_query = lambda ids, _embedding: history.extend(ids)
    tracker.forget_documents = lambda _ids: history.clear()
    proxy = RetrieverProxy(
        collection=PausedCollection(), embed_fn=lambda _: [[1.0]], tracker=tracker,
        quarantine=Quarantine(),
        cfg=SimpleNamespace(top_k=1, candidate_buffer=0, top_rank_threshold=1),
        emit=lambda *_args, **_kwargs: None,
    )
    def update():
        proxy.upsert_documents([("doc", "replacement")])
        updated.set()

    with ThreadPoolExecutor(max_workers=2) as workers:
        retrieval = workers.submit(proxy.retrieve, "query")
        assert entered.wait(3)
        mutation = workers.submit(update)
        try:
            assert not updated.wait(0.1)
        finally:
            release.set()
        retrieval.result(timeout=3)
        mutation.result(timeout=3)
    assert history == []
    assert proxy.collection.documents["doc"] == "replacement"
