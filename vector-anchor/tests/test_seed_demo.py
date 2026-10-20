"""The demo-corpus seed endpoint loads the local fixture and fails closed."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from src.main import SeedDemoRequest, _demo_corpus, app, seed_demo


def request(authorization: str = "") -> Request:
    headers = []
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    return Request({"type": "http", "headers": headers})


class FakeProxy:
    """Records what the endpoint asked the collection to hold."""

    def __init__(self, admin_token: str | None = "correct-token-0000") -> None:
        self.cfg = SimpleNamespace(admin_token=admin_token)
        self.calls: list[list[tuple[str, str]]] = []

    def upsert_documents(self, documents: list[tuple[str, str]]) -> int:
        self.calls.append(list(documents))
        return sum(len(call) for call in self.calls)


def test_seed_demo_loads_the_clean_corpus():
    proxy = FakeProxy()
    app.state.proxy = proxy

    result = seed_demo(SeedDemoRequest(), request("Bearer correct-token-0000"))

    assert result["added"] == 60
    assert result["bait"] is False
    ids = [doc_id for doc_id, _ in proxy.calls[0]]
    assert "garden-1" in ids
    assert "poison-universal-bait" not in ids


def test_seed_demo_can_include_the_bait_fixture():
    proxy = FakeProxy()
    app.state.proxy = proxy

    result = seed_demo(
        SeedDemoRequest(include_bait=True), request("Bearer correct-token-0000")
    )

    assert result["added"] == 61
    assert result["bait"] is True
    ids = [doc_id for doc_id, _ in proxy.calls[0]]
    assert "poison-universal-bait" in ids


def test_seed_demo_is_idempotent_for_the_same_ids():
    proxy = FakeProxy()
    app.state.proxy = proxy

    seed_demo(SeedDemoRequest(), request("Bearer correct-token-0000"))
    second = seed_demo(SeedDemoRequest(), request("Bearer correct-token-0000"))

    assert second["total"] == 120
    assert proxy.calls[0] == proxy.calls[1]


def test_seed_demo_fails_closed_without_a_valid_admin_credential():
    app.state.proxy = FakeProxy(admin_token=None)
    with pytest.raises(HTTPException) as unavailable:
        seed_demo(SeedDemoRequest(), request("Bearer correct-token-0000"))
    assert unavailable.value.status_code == 503

    app.state.proxy = FakeProxy()
    with pytest.raises(HTTPException) as rejected:
        seed_demo(SeedDemoRequest(), request("Bearer wrong-token-00000"))
    assert rejected.value.status_code == 401


def test_demo_corpus_fixture_holds_the_clean_documents_and_one_bait():
    clean, bait_id, bait_text = _demo_corpus()
    assert len(clean) == 60
    assert all(doc_id and text for doc_id, text in clean)
    assert bait_id == "poison-universal-bait"
    assert bait_text.strip()
