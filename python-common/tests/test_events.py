from __future__ import annotations

import json

from monolith_events.events import EventContext, EventOutbox, make_emitter


def outbox(tmp_path, **limits) -> EventOutbox:
    return EventOutbox(
        str(tmp_path / "outbox.db"),
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        start_worker=False,
        **limits,
    )


def test_pending_and_dead_letter_storage_are_bounded(tmp_path):
    delivery = outbox(tmp_path, max_pending=2, max_dead=1)
    for index in range(3):
        delivery.enqueue(f"event-{index}", b"{}")

    assert delivery.stats()["pending"] == 2
    assert delivery.stats()["dead"] == 1
    delivery.close()


def test_transient_failures_stop_at_the_attempt_cap(tmp_path):
    delivery = outbox(tmp_path, max_attempts=2)
    delivery._post = lambda _payload: (503, "http 503")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")

    delivery.flush_once()
    with delivery._lock:
        delivery._connection.execute(
            "update event_outbox set next_attempt_ms = 0 where event_id = 'event-1'"
        )
        delivery._connection.commit()
    delivery.flush_once()

    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 1
    delivery.close()


def test_permanent_rejections_are_dead_lettered_immediately(tmp_path):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")
    delivery.flush_once()

    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 1
    delivery.close()


def test_successful_delivery_removes_the_spooled_record(tmp_path):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (202, "")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")
    delivery.flush_once()

    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 0
    delivery.close()


def test_emitter_stamps_policy_and_resource_evidence(capsys):
    emit = make_emitter("vector-anchor", None, None, "unused.db")
    emit(
        "corpus_poison_quarantine",
        "critical",
        {"score": 0.9},
        EventContext(trace_id="trace-1"),
        resource_type="document",
        resource_id="doc-1",
        outcome="quarantined",
        policy_version="vector-anchor/1",
    )
    event = json.loads(capsys.readouterr().err)

    assert event["resource_type"] == "document"
    assert event["resource_id"] == "doc-1"
    assert event["outcome"] == "quarantined"
    assert event["policy_version"] == "vector-anchor/1"
