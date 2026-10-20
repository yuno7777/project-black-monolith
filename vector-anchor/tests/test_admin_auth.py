"""Administrative routes fail closed and accept only the configured bearer."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from src.events import EventOutbox
from src.frequency_tracker import FrequencyTracker
from src.main import (
    _admin_credential_valid,
    _require_admin,
    _require_admin_token,
    admin_replay_dead_letters,
    app,
    delete_quarantined_document,
)
from src.quarantine import Quarantine, QuarantinedDoc
from src.retriever_proxy import RetrieverProxy


def request(authorization: str = "", query_string: str = "") -> Request:
    headers = []
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    return Request(
        {
            "type": "http",
            "headers": headers,
            "query_string": query_string.encode(),
        }
    )


def test_admin_auth_fails_closed_without_configuration():
    assert not _admin_credential_valid(None, "Bearer anything")


def test_admin_auth_requires_the_bearer_scheme():
    assert not _admin_credential_valid("correct-token-0000", "correct-token-0000")
    assert not _admin_credential_valid("correct-token-0000", "Basic correct-token-0000")


def test_admin_auth_rejects_wrong_and_accepts_exact_token():
    assert not _admin_credential_valid("correct-token-0000", "Bearer wrong-token-00000")
    assert _admin_credential_valid("correct-token-0000", "Bearer correct-token-0000")


def test_admin_guard_distinguishes_unconfigured_wrong_and_valid_credentials():
    app.state.proxy = SimpleNamespace(cfg=SimpleNamespace(admin_token=None))
    with pytest.raises(HTTPException) as unavailable:
        _require_admin(request())
    assert unavailable.value.status_code == 503

    app.state.proxy = SimpleNamespace(cfg=SimpleNamespace(admin_token="correct-token-0000"))
    with pytest.raises(HTTPException) as rejected:
        _require_admin(request("Bearer wrong-token-00000"))
    assert rejected.value.status_code == 401

    _require_admin(request("Bearer correct-token-0000"))
    _require_admin_token(request("Bearer correct-token-0000"))


def test_delete_quarantine_doc_releases_quarantine_and_resets_tracker():
    tracker = FrequencyTracker(
        min_distinct_topics=2,
        topic_similarity=0.2,
        retention_horizon=500,
        max_queries_per_doc=8,
    )
    tracker.record_query(["doc-1", "doc-2"], [1.0, 0.0])
    tracker._quarantined.add("doc-1")
    quarantine = Quarantine()
    quarantine.add(QuarantinedDoc("doc-1", "universal_bait", 4, "preview-1", 100))
    quarantine.add(QuarantinedDoc("doc-2", "universal_bait", 4, "preview-2", 200))
    saved = []

    class FakeStore:
        def save(self, _t, q):
            saved.append(q.list_ids())

    app.state.proxy = RetrieverProxy(
        collection=SimpleNamespace(),
        embed_fn=lambda _q: [[1.0, 0.0]],
        tracker=tracker,
        quarantine=quarantine,
        cfg=SimpleNamespace(admin_token="correct-token-0000", state_flush_interval_ms=60_000),
        emit=lambda *_args, **_kwargs: None,
        state_store=FakeStore(),  # type: ignore[arg-type]
    )

    with pytest.raises(HTTPException) as rejected:
        delete_quarantined_document("doc-1", request("Bearer wrong-token-00000"))
    assert rejected.value.status_code == 401

    res = delete_quarantined_document("doc-1", request("Bearer correct-token-0000"))
    assert res == {"doc_id": "doc-1", "released": True, "quarantined_count": 1}
    assert not quarantine.is_quarantined("doc-1")
    assert "doc-1" not in tracker._docs
    assert "doc-1" not in tracker._quarantined
    assert saved == [["doc-2"]]

    res_again = delete_quarantined_document("doc-1", request("Bearer correct-token-0000"))
    assert res_again == {"doc_id": "doc-1", "released": False, "quarantined_count": 1}


def test_admin_replay_dead_letters_route(tmp_path):
    outbox = EventOutbox(
        str(tmp_path / "outbox.db"),
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        start_worker=False,
    )
    outbox._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    outbox.enqueue("dead-1", b"{}")
    outbox.flush_once()
    assert outbox.stats()["dead"] == 1

    app.state.proxy = SimpleNamespace(
        cfg=SimpleNamespace(admin_token="correct-token-0000"),
        emit=SimpleNamespace(outbox=outbox),
    )

    with pytest.raises(HTTPException) as rejected:
        admin_replay_dead_letters(request("Bearer wrong-token-00000"))
    assert rejected.value.status_code == 401

    result = admin_replay_dead_letters(request("Bearer correct-token-0000"))
    assert result == {"replayed": 1}
    assert outbox.stats()["pending"] == 1
    assert outbox.stats()["dead"] == 0
    outbox.close()


def test_admin_replay_dead_letters_route_is_scoped_to_one_tenant(tmp_path):
    outbox = EventOutbox(
        str(tmp_path / "outbox.db"),
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        start_worker=False,
    )
    outbox._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    outbox.enqueue("dead-acme", b'{"event_id":"dead-acme","tenant_id":"acme"}')
    outbox.enqueue("dead-other", b'{"event_id":"dead-other","tenant_id":"other"}')
    outbox.flush_once()
    assert outbox.stats()["dead"] == 2

    app.state.proxy = SimpleNamespace(
        cfg=SimpleNamespace(admin_token="correct-token-0000"),
        emit=SimpleNamespace(outbox=outbox),
    )

    # An operator for one tenant has no authority over another tenant's
    # evidence, and the count they are given is their own.
    result = admin_replay_dead_letters(
        request("Bearer correct-token-0000", "tenant=acme")
    )
    assert result == {"replayed": 1}
    assert outbox.stats()["pending"] == 1
    assert outbox.stats()["dead"] == 1
    outbox.close()


def test_admin_replay_dead_letters_route_refuses_a_tenant_it_cannot_read(tmp_path):
    outbox = EventOutbox(
        str(tmp_path / "outbox.db"),
        "https://dashboard.invalid/api/ingest",
        "test-token-value",
        start_worker=False,
    )
    outbox._post = lambda _payload: (422, "http 422")  # type: ignore[method-assign]
    outbox.enqueue("dead-acme", b'{"event_id":"dead-acme","tenant_id":"acme"}')
    outbox.flush_once()

    app.state.proxy = SimpleNamespace(
        cfg=SimpleNamespace(admin_token="correct-token-0000"),
        emit=SimpleNamespace(outbox=outbox),
    )

    # A tenant nobody can read must not fall back to the whole spool: the
    # event stays dead rather than being handed to a tenant nobody asked
    # about.
    with pytest.raises(HTTPException) as refused:
        admin_replay_dead_letters(request("Bearer correct-token-0000", "tenant="))
    assert refused.value.status_code == 422
    assert outbox.stats()["dead"] == 1
    assert outbox.stats()["pending"] == 0
    outbox.close()
