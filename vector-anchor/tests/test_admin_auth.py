"""Administrative routes fail closed and accept only the configured bearer."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from src.main import _admin_credential_valid, _require_admin, app


def request(authorization: str = "") -> Request:
    headers = []
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    return Request({"type": "http", "headers": headers})

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
