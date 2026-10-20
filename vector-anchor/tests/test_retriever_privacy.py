"""Agent queries and corpus text must not be copied into security telemetry."""

import hashlib
from types import SimpleNamespace

from src.events import EventContext
from src.quarantine import Quarantine, QuarantinedDoc
from src.retriever_proxy import RetrieverProxy

# Every retrieval names the session it belongs to: a retrieval that cannot
# be attributed to a session is refused, because the cross-layer circuit
# breaker revokes sessions and cannot act on one it cannot name.
SESSION = EventContext(session_id="privacy-test-session")


class Collection:
    def __init__(self, document: str):
        self.document = document
        self.last_n_results = None

    def query(self, **kwargs):
        assert kwargs["query_embeddings"] == [[1.0]]
        assert "query_texts" not in kwargs
        self.last_n_results = kwargs["n_results"]
        return {
            "ids": [["doc-1"]],
            "documents": [[self.document]],
            "distances": [[0.1]],
        }


class Tracker:
    def __init__(self, anomalous: bool):
        self.anomalous = anomalous

    def record_query(self, _ids, _embedding):
        pass

    def is_anomalous(self, _doc_id):
        return self.anomalous

    def evaluate(self, doc_id):
        return SimpleNamespace(
            doc_id=doc_id,
            score=4,
            distinct_topics=4,
            total_queries=4,
        )


def proxy(document: str, anomalous: bool, events: list, **cfg_overrides):
    cfg_values = dict(
        top_k=1,
        candidate_buffer=0,
        top_rank_threshold=1,
        min_distinct_topics=4,
        state_flush_interval_ms=0,
        log_clean_retrievals=True,
    )
    cfg_values.update(cfg_overrides)
    return RetrieverProxy(
        collection=Collection(document),
        embed_fn=lambda _queries: [[1.0]],
        tracker=Tracker(anomalous),
        quarantine=Quarantine(),
        cfg=SimpleNamespace(**cfg_values),
        emit=lambda event_type, severity, details, _ctx, **_evidence: events.append(
            (event_type, severity, details)
        ),
    )


def test_retrieval_event_fingerprints_instead_of_logging_query():
    events = []
    secret_query = "find records for private-user@example.com"
    response = proxy("safe document", False, events).retrieve(secret_query, None, SESSION)

    assert response["query"] == secret_query, "the direct caller still receives its query"
    details = events[-1][2]
    assert secret_query not in repr(details)
    assert details["query_sha256"] == hashlib.sha256(
        secret_query.encode("utf-8")
    ).hexdigest()
    assert details["query_chars"] == len(secret_query)


def test_quarantine_event_keeps_corpus_preview_out_of_telemetry():
    events = []
    secret_document = "poison bait containing sk-abcdefghijklmnopqrstuvwxyz"
    instance = proxy(secret_document, True, events)
    instance.retrieve("ordinary query", None, SESSION)

    quarantine_event = next(event for event in events if event[0] == "corpus_poison_quarantine")
    details = quarantine_event[2]
    assert secret_document not in repr(details)
    assert details["document_sha256"] == hashlib.sha256(
        secret_document.encode("utf-8")
    ).hexdigest()
    assert instance.quarantine.all()[0].preview in secret_document


def test_log_clean_retrievals_false_suppresses_only_clean_retrieval_events():
    clean_events = []
    clean_instance = proxy(
        "safe document", False, clean_events, log_clean_retrievals=False
    )
    clean_instance.retrieve("ordinary query", None, SESSION)
    assert clean_events == []

    filtered_events = []
    filtered_instance = proxy(
        "poison document", True, filtered_events, log_clean_retrievals=False
    )
    filtered_instance.retrieve("ordinary query", None, SESSION)
    event_types = [event[0] for event in filtered_events]
    assert "corpus_poison_quarantine" in event_types
    assert "retrieval" in event_types


def test_dynamic_candidate_expansion_prevents_quarantine_starvation():
    class MultiDocCollection:
        def __init__(self):
            self.requested_n: list[int] = []

        def query(self, **kwargs):
            n = kwargs["n_results"]
            self.requested_n.append(n)
            all_ids = [f"bait-{i}" for i in range(10)] + ["clean-1", "clean-2", "clean-3"]
            selected = all_ids[:n]
            return {
                "ids": [selected],
                "documents": [[f"text for {doc_id}" for doc_id in selected]],
                "distances": [[0.01 * idx for idx in range(len(selected))]],
            }

    collection = MultiDocCollection()
    quarantine = Quarantine()
    for i in range(10):
        quarantine.add(QuarantinedDoc(f"bait-{i}", "already_quarantined", 4, "bait", 1))

    instance = RetrieverProxy(
        collection=collection,
        embed_fn=lambda _queries: [[1.0]],
        tracker=Tracker(False),
        quarantine=quarantine,
        cfg=SimpleNamespace(
            top_k=3,
            candidate_buffer=5,
            top_rank_threshold=2,
            min_distinct_topics=4,
            state_flush_interval_ms=0,
            log_clean_retrievals=True,
        ),
        emit=lambda *_args, **_kwargs: None,
    )
    response = instance.retrieve("topic query", None, SESSION)

    assert collection.requested_n == [3 + 5 + 10]
    assert [r["id"] for r in response["results"]] == ["clean-1", "clean-2", "clean-3"]
    assert len(response["withheld"]) == 10


def test_debounced_state_persistence_flushes_immediately_on_quarantine_and_shutdown():
    saves = []

    class FakeStateStore:
        def save(self, tracker, quarantine):
            saves.append(len(quarantine.list_ids()))

    instance = RetrieverProxy(
        collection=Collection("safe document"),
        embed_fn=lambda _queries: [[1.0]],
        tracker=Tracker(False),
        quarantine=Quarantine(),
        cfg=SimpleNamespace(
            top_k=1,
            candidate_buffer=0,
            top_rank_threshold=1,
            min_distinct_topics=4,
            state_flush_interval_ms=60_000,
            log_clean_retrievals=True,
        ),
        emit=lambda *_args, **_kwargs: None,
        state_store=FakeStateStore(),  # type: ignore[arg-type]
    )

    # First retrieval triggers initial flush since _last_state_flush_ms starts at 0.
    instance.retrieve("query-1", None, SESSION)
    assert len(saves) == 1

    # Second clean retrieval within the debounce window skips disk I/O.
    instance.retrieve("query-2", None, SESSION)
    assert len(saves) == 1
    assert instance._state_dirty is True

    # Newly quarantined document forces immediate persistence even inside interval.
    instance.tracker.anomalous = True  # type: ignore[attr-defined]
    instance.retrieve("query-3", None, SESSION)
    assert len(saves) == 2
    assert saves[-1] == 1
    assert instance._state_dirty is False

    # Subsequent retrieval marks dirty; explicit flush_state() persists immediately.
    instance.retrieve("query-4", None, SESSION)
    assert len(saves) == 2
    assert instance.flush_state() is True
    assert len(saves) == 3
    assert instance._state_dirty is False
