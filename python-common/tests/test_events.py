from __future__ import annotations

import json

import pytest
from monolith_events.events import (
    AGENT_HEADER,
    EventContext,
    EventOutbox,
    _NoRedirect,
    context_from_headers,
    make_emitter,
    replay_dead_letters,
)


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


@pytest.mark.parametrize(
    "url",
    [
        "http://dashboard.example/api/ingest",
        "https://user:password@dashboard.example/api/ingest",
        "https://dashboard.example/api/ingest#secret",
        "file:///tmp/ingest",
    ],
)
def test_outbox_rejects_unsafe_delivery_urls(tmp_path, url):
    with pytest.raises(ValueError, match="HTTPS"):
        EventOutbox(str(tmp_path / "outbox.db"), url, "test-token-value")


def test_outbox_allows_loopback_http_for_local_development(tmp_path):
    delivery = EventOutbox(
        str(tmp_path / "outbox.db"),
        "http://127.0.0.1:3000/api/ingest",
        "test-token-value",
        start_worker=False,
    )
    delivery.close()


def test_plaintext_service_delivery_requires_explicit_opt_in(tmp_path):
    delivery = EventOutbox(
        str(tmp_path / "outbox.db"),
        "http://dashboard:3000/api/ingest",
        "test-token-value",
        start_worker=False,
        allow_insecure_http=True,
    )
    delivery.close()


def test_delivery_never_forwards_bearer_credentials_across_redirects():
    assert _NoRedirect().redirect_request(None, None, 307, "redirect", {}, "https://other.invalid") is None


@pytest.mark.parametrize(
    "token",
    ["short", "token with spaces 0000", "token\r\ninjected-0000", "x" * 513],
)
def test_outbox_rejects_unsafe_bearer_tokens(tmp_path, token):
    with pytest.raises(ValueError, match="header-safe"):
        EventOutbox(
            str(tmp_path / "outbox.db"),
            "https://dashboard.invalid/api/ingest",
            token,
            start_worker=False,
        )


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


def test_outbox_rejects_oversized_or_malformed_records(tmp_path):
    delivery = outbox(tmp_path)
    for event_id, payload in [
        ("", b"{}"),
        ("event\nforged", b"{}"),
        ("x" * 129, b"{}"),
        ("event-1", b""),
        ("event-1", b"x" * (256 * 1024 + 1)),
    ]:
        with pytest.raises(ValueError):
            delivery.enqueue(event_id, payload)
    assert delivery.stats()["pending"] == 0
    delivery.close()


def test_correlation_headers_reject_controls_and_overlong_values():
    assert context_from_headers({AGENT_HEADER: " agent-1 "}).agent_id == "agent-1"
    assert context_from_headers({AGENT_HEADER: "agent\nforged"}).agent_id is None
    assert context_from_headers({AGENT_HEADER: "x" * 129}).agent_id is None
    assert context_from_headers({AGENT_HEADER: "😀" * 33}).agent_id is None


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


def test_outbox_creates_composite_status_indexes(tmp_path):
    delivery = outbox(tmp_path)
    indexes = {
        row[1]: [
            col[2]
            for col in delivery._connection.execute(f"pragma index_info({row[1]})").fetchall()
        ]
        for row in delivery._connection.execute("pragma index_list(event_outbox)").fetchall()
    }
    assert indexes["idx_event_outbox_status_next"] == [
        "status",
        "next_attempt_ms",
        "created_ms",
    ]
    assert indexes["idx_event_outbox_status_updated"] == [
        "status",
        "updated_ms",
    ]
    delivery.close()


def test_replay_dead_letters_resets_dead_rows_and_wakes_worker(tmp_path):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b'{"id":1}')
    delivery.enqueue("event-2", b'{"id":2}')
    delivery.flush_once()

    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 2
    delivery._wake.clear()

    replayed = replay_dead_letters(delivery)
    assert replayed == 2
    assert delivery._wake.is_set()
    assert delivery.stats()["pending"] == 2
    assert delivery.stats()["dead"] == 0

    rows = delivery._connection.execute(
        "select status, attempts, next_attempt_ms, last_error, updated_ms from event_outbox order by event_id"
    ).fetchall()
    for status, attempts, next_attempt_ms, last_error, updated_ms in rows:
        assert status == "pending"
        assert attempts == 0
        assert next_attempt_ms == 0
        assert last_error is None
        assert updated_ms > 0

    assert replay_dead_letters(delivery) == 0
    assert replay_dead_letters(None) == 0

    delivery._post = lambda _payload: (202, "")  # type: ignore[method-assign]
    delivery.flush_once()
    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 0
    delivery.close()

