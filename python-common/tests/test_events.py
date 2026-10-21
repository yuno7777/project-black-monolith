from __future__ import annotations

import json
import sqlite3

import pytest
from monolith_events.events import (
    AGENT_HEADER,
    EventContext,
    EventOutbox,
    _NoRedirect,
    context_from_headers,
    credential_transport_is_trusted,
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


@pytest.mark.parametrize(
    "url",
    [
        "https://api.anthropic.com/v1/messages",
        "http://127.0.0.1:8100/v1/messages",
        "http://localhost:8100/v1/messages",
        "http://[::1]:8100/v1/messages",
    ],
)
def test_the_credential_transport_rule_trusts_https_and_loopback(url):
    assert credential_transport_is_trusted(url) is True


@pytest.mark.parametrize(
    "url",
    [
        # Plain HTTP to anywhere that is not loopback: the credential would
        # be on the wire, in front of whoever answers.
        "http://model.example.com/v1/messages",
        "http://10.0.0.5:8100/v1/messages",
        # A credential in the URL is a credential in a log line, a proxy's
        # request line and a process listing.
        "https://user:password@model.example.com/v1/messages",
        # A fragment never reaches the server; a credential there is a
        # credential in the wrong place.
        "https://model.example.com/v1/messages#secret",
        # Not a transport at all.
        "file:///tmp/messages",
        # No host to trust.
        "https:///v1/messages",
    ],
)
def test_the_credential_transport_rule_refuses_the_rest(url):
    assert credential_transport_is_trusted(url) is False


def test_the_credential_transport_rule_needs_the_operator_to_opt_in():
    """Plain HTTP to a non-loopback host is refused by default.

    The escape hatch has to be asked for by name: an operator whose model
    service is on a trusted network can say so, and an operator who has
    mistyped a host cannot enable it by accident.
    """
    url = "http://model.example.com/v1/messages"
    assert credential_transport_is_trusted(url) is False
    assert credential_transport_is_trusted(url, allow_insecure=True) is True


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
    assert indexes["idx_event_outbox_tenant_status"] == [
        "tenant_id",
        "status",
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


def test_a_spooled_event_is_attributed_to_the_tenant_it_names(tmp_path):
    delivery = outbox(tmp_path)
    delivery.enqueue("event-1", b'{"event_id":"event-1","tenant_id":"acme"}')
    rows = delivery._connection.execute(
        "select tenant_id from event_outbox where event_id = 'event-1'"
    ).fetchall()
    assert rows == [("acme",)]
    delivery.close()


def test_a_tenant_scoped_replay_leaves_another_tenants_dead_letters_alone(tmp_path):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    delivery.enqueue("event-acme", b'{"event_id":"event-acme","tenant_id":"acme"}')
    delivery.enqueue("event-other", b'{"event_id":"event-other","tenant_id":"other"}')
    delivery.flush_once()
    assert delivery.stats()["dead"] == 2

    # An operator for one tenant has no authority over another tenant's
    # evidence, and the count they are given is their own.
    assert replay_dead_letters(delivery, tenant_id="acme") == 1
    assert delivery.stats()["pending"] == 1
    assert delivery.stats()["dead"] == 1

    rows = delivery._connection.execute(
        "select event_id, tenant_id, status from event_outbox order by event_id"
    ).fetchall()
    assert rows == [
        ("event-acme", "acme", "pending"),
        ("event-other", "other", "dead"),
    ]
    delivery.close()


def test_a_tenant_that_cannot_be_read_is_refused_rather_than_widened(tmp_path):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b'{"event_id":"event-1","tenant_id":"acme"}')
    delivery.flush_once()

    # An unreadable scope must never fall back to "everything": the event
    # stays dead rather than being handed to a tenant nobody asked about.
    with pytest.raises(ValueError):
        delivery.replay_dead_letters(tenant_id="")
    with pytest.raises(ValueError):
        delivery.replay_dead_letters(tenant_id="acme\nother")
    assert delivery.stats()["dead"] == 1
    assert delivery.stats()["pending"] == 0
    delivery.close()


def test_an_outbox_written_before_the_tenant_column_still_gets_attributed(tmp_path):
    path = str(tmp_path / "legacy.db")
    connection = sqlite3.connect(path)
    connection.execute(
        """create table event_outbox (
            event_id text primary key,
            payload blob not null,
            attempts integer not null default 0,
            next_attempt_ms integer not null,
            status text not null default 'pending',
            last_error text,
            created_ms integer not null,
            updated_ms integer not null
        )"""
    )
    connection.execute(
        "insert into event_outbox values (?, ?, 0, 0, 'dead', null, 1, 1)",
        ("legacy-1", b'{"event_id":"legacy-1","tenant_id":"acme"}'),
    )
    connection.commit()
    connection.close()

    delivery = EventOutbox(
        path,
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        start_worker=False,
    )
    # Evidence that predates the column is still evidence: it is attributed
    # from the payload it carries, not skipped.
    rows = delivery._connection.execute(
        "select tenant_id from event_outbox where event_id = 'legacy-1'"
    ).fetchall()
    assert rows == [("acme",)]
    assert delivery.replay_dead_letters(tenant_id="acme") == 1
    delivery.close()

