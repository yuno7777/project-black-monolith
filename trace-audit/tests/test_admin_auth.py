"""Administrative detector metadata is protected and fails closed."""

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


def test_admin_auth_requires_an_exact_bearer_credential():
    assert not _admin_credential_valid(None, "Bearer anything")
    assert not _admin_credential_valid("correct-token-0000", "Basic correct-token-0000")
    assert not _admin_credential_valid("correct-token-0000", "Bearer wrong-token-00000")
    assert _admin_credential_valid("correct-token-0000", "Bearer correct-token-0000")


def test_admin_guard_distinguishes_unconfigured_wrong_and_valid_credentials():
    app.state.cfg = SimpleNamespace(admin_token=None)
    with pytest.raises(HTTPException) as unavailable:
        _require_admin(request())
    assert unavailable.value.status_code == 503

    app.state.cfg = SimpleNamespace(admin_token="correct-token-0000")
    with pytest.raises(HTTPException) as rejected:
        _require_admin(request("Bearer wrong-token-00000"))
    assert rejected.value.status_code == 401

    _require_admin(request("Bearer correct-token-0000"))
