"""Detector state transitions are serialized across FastAPI worker threads."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from src.quarantine import Quarantine
from src.retriever_proxy import RetrieverProxy


class Collection:
    def query(self, **_kwargs):
        return {
            "ids": [["doc"]],
            "documents": [["document"]],
            "distances": [[0.1]],
        }


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
        emit=lambda *_args: None,
    )
    barrier = threading.Barrier(8)

    def retrieve(index):
        barrier.wait()
        return proxy.retrieve(f"query-{index}")

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(retrieve, range(8)))

    assert len(results) == 8
    assert tracker.max_active == 1
