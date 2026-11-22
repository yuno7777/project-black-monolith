import hashlib
import json

import pytest
from monolith_events.workload import WORKLOAD_HEADER, WorkloadDenied, authorize_workload

TOKEN = "workload-fixture-token-for-testing-only"


@pytest.fixture
def grant(monkeypatch):
    monkeypatch.setenv("MONOLITH_WORKLOAD_GRANTS_JSON", json.dumps([{
        "token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest(),
        "agent_id": "triage-agent",
        "session_id": "triage-session",
    }]))


def authorize(headers):
    return authorize_workload(
        headers, tenant="customer-a", module="vector-anchor",
        dashboard_url="http://localhost:3000/api/ingest", event_token="module-fixture-token",
        allow_insecure_dashboard=False,
    )


@pytest.mark.usefixtures("grant")
@pytest.mark.parametrize(("headers", "code"), [
    ({}, 401),
    ({WORKLOAD_HEADER: "another-long-workload-fixture-token"}, 401),
    ({WORKLOAD_HEADER: TOKEN, "x-monolith-tenant-id": "customer-b"}, 403),
    ({WORKLOAD_HEADER: TOKEN, "x-monolith-agent-id": "other-agent"}, 403),
    ({WORKLOAD_HEADER: TOKEN, "x-monolith-session-id": "other-session"}, 403),
])
def test_rejects_missing_credentials_and_identity_overrides(headers, code):
    with pytest.raises(WorkloadDenied) as raised:
        authorize(headers)
    assert raised.value.status == code


@pytest.mark.usefixtures("grant")
@pytest.mark.parametrize(("body", "code"), [
    (b'{"revoked":false}', None),
    (b'{"revoked":true}', 403),
    (b'{"revoked_sessions":[]}', 503),
])
def test_checks_exact_revocation_before_returning_identity(monkeypatch, body, code):
    from io import BytesIO

    class Opener:
        def open(self, request, timeout):
            assert request.full_url.endswith("?agent_id=triage-agent&session_id=triage-session")
            assert request.get_header("X-monolith-tenant-id") == "customer-a"
            assert request.get_header("Authorization") == "Bearer module-fixture-token"
            assert timeout == 2
            return BytesIO(body)

    monkeypatch.setattr("urllib.request.build_opener", lambda *_: Opener())
    if code:
        with pytest.raises(WorkloadDenied) as raised:
            authorize({WORKLOAD_HEADER: TOKEN})
        assert raised.value.status == code
    else:
        ctx = authorize({WORKLOAD_HEADER: TOKEN})
        assert (ctx.tenant_id, ctx.agent_id, ctx.session_id) == ("customer-a", "triage-agent", "triage-session")
        assert ctx.workload_authenticated


def test_invalid_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("MONOLITH_WORKLOAD_GRANTS_JSON", "[]")
    with pytest.raises(WorkloadDenied) as raised:
        authorize({WORKLOAD_HEADER: TOKEN})
    assert raised.value.status == 503
