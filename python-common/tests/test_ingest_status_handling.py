"""How the module's outbox reads the dashboard's answer to a delivery.

The ingest path answers with two very different kinds of "no". A `422` says
*this event is unacceptable* — retrying it would fail the same way forever,
so it is dead-lettered. A `429` says *not now* — the dashboard's rate limit
is spent and the event itself is fine, so it must be retried.

The rate limit is new, and it is the first thing the dashboard answers with
a `429`. A module that classified `429` as permanent would dead-letter every
event it filed during a burst — which is exactly when the detections matter
most. These tests pin the classification and the two behaviours it implies.
"""

from __future__ import annotations

import pytest
from monolith_events.events import (
    PERMANENT_HTTP_STATUSES,
    EventOutbox,
    now_ms,
)


def outbox(tmp_path, **limits) -> EventOutbox:
    return EventOutbox(
        str(tmp_path / "outbox.db"),
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        start_worker=False,
        **limits,
    )


def row(delivery: EventOutbox, event_id: str) -> tuple[str, int, int, str | None]:
    with delivery._lock:
        found = delivery._connection.execute(
            "select status, attempts, next_attempt_ms, last_error"
            " from event_outbox where event_id = ?",
            (event_id,),
        ).fetchone()
    assert found is not None, "the spooled record disappeared"
    return found[0], found[1], found[2], found[3]


def make_eligible_again(delivery: EventOutbox, event_id: str) -> None:
    """Make a backoff-backed record due again, without waiting for it."""
    with delivery._lock:
        delivery._connection.execute(
            "update event_outbox set next_attempt_ms = 0 where event_id = ?",
            (event_id,),
        )
        delivery._connection.commit()


def test_the_rate_limit_status_is_not_classified_as_permanent():
    # A permanent status is dead-lettered on the first answer. `429` is the
    # dashboard saying "not now" — the event is fine, the budget is spent.
    assert 429 not in PERMANENT_HTTP_STATUSES
    # The statuses that really are permanent: a malformed event, a bad token,
    # a body the dashboard will not accept.
    for status in (400, 401, 403, 413, 422):
        assert status in PERMANENT_HTTP_STATUSES


def test_a_rate_limited_delivery_is_retried_rather_than_dead_lettered(tmp_path):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (429, "http 429")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")

    delivery.flush_once()

    status, attempts, _next_attempt, error = row(delivery, "event-1")
    assert status == "pending", "a rate-limited event must stay in the spool"
    assert attempts == 1
    assert error is not None and "429" in error
    assert delivery.stats()["dead"] == 0
    delivery.close()


def test_a_rate_limited_delivery_is_not_retried_immediately(tmp_path):
    # The retry has to wait. A tight loop would spend the budget again
    # immediately and turn one rate-limited module into a busy one.
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (429, "http 429")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")

    before = now_ms()
    delivery.flush_once()

    _status, _attempts, next_attempt, _error = row(delivery, "event-1")
    assert next_attempt > before, "the record must be scheduled into the future"
    delivery.close()


def test_a_rate_limited_delivery_still_stops_at_the_attempt_cap(tmp_path):
    # A rate limit that never lifts must not retry forever. The cap is what
    # turns "retried" into "eventually dead-lettered".
    delivery = outbox(tmp_path, max_attempts=2)
    delivery._post = lambda _payload: (429, "http 429")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")

    delivery.flush_once()
    make_eligible_again(delivery, "event-1")
    delivery.flush_once()

    status, attempts, _next_attempt, error = row(delivery, "event-1")
    assert status == "dead"
    assert attempts == 2
    assert error is not None
    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 1
    delivery.close()


def test_a_rejected_event_is_dead_lettered_with_its_reason(tmp_path):
    # The other kind of "no": the event itself is unacceptable. Retrying it
    # would fail the same way forever, so it is dead-lettered at once and the
    # reason is kept, so an operator can see what the dashboard objected to.
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")

    delivery.flush_once()

    status, attempts, _next_attempt, error = row(delivery, "event-1")
    assert status == "dead"
    assert attempts == 1, "a permanent rejection is not retried"
    assert error is not None and "422" in error
    assert delivery.stats()["pending"] == 0
    assert delivery.stats()["dead"] == 1
    delivery.close()


@pytest.mark.parametrize("status", [400, 401, 403, 413, 422])
def test_every_permanent_status_dead_letters_on_the_first_answer(tmp_path, status):
    delivery = outbox(tmp_path)
    delivery._post = lambda _payload: (status, f"http {status}")  # type: ignore[method-assign]
    delivery.enqueue("event-1", b"{}")

    delivery.flush_once()

    row_status, attempts, _next_attempt, _error = row(delivery, "event-1")
    assert row_status == "dead"
    assert attempts == 1
    delivery.close()
