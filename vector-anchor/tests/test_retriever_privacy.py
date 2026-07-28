"""Agent queries and corpus text must not be copied into security telemetry."""

import hashlib
from types import SimpleNamespace

from src.quarantine import Quarantine
from src.retriever_proxy import RetrieverProxy


class Collection:
    def __init__(self, document: str):
        self.document = document

    def query(self, **_kwargs):
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


def proxy(document: str, anomalous: bool, events: list):
    return RetrieverProxy(
        collection=Collection(document),
        embed_fn=lambda _queries: [[1.0]],
        tracker=Tracker(anomalous),
        quarantine=Quarantine(),
        cfg=SimpleNamespace(
            top_k=1,
            candidate_buffer=0,
            top_rank_threshold=1,
            min_distinct_topics=4,
        ),
        emit=lambda event_type, severity, details, _ctx: events.append(
            (event_type, severity, details)
        ),
    )


def test_retrieval_event_fingerprints_instead_of_logging_query():
    events = []
    secret_query = "find records for private-user@example.com"
    response = proxy("safe document", False, events).retrieve(secret_query)

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
    instance.retrieve("ordinary query")

    quarantine_event = next(event for event in events if event[0] == "corpus_poison_quarantine")
    details = quarantine_event[2]
    assert secret_document not in repr(details)
    assert details["document_sha256"] == hashlib.sha256(
        secret_document.encode("utf-8")
    ).hexdigest()
    assert instance.quarantine.all()[0].preview in secret_document
