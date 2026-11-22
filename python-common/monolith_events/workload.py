"""Session-bound credentials for agent-facing requests in a tenant's services."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import replace
from hmac import compare_digest

from .events import (
    AGENT_HEADER,
    SESSION_HEADER,
    TENANT_HEADER,
    EventContext,
    _NoRedirect,
    _valid_bearer_token,
    context_from_headers,
    credential_transport_is_trusted,
    revocation_poll_url,
)

WORKLOAD_HEADER = "x-monolith-workload-token"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class WorkloadDenied(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _grants(raw: str) -> dict[str, tuple[str, str]]:
    entries = json.loads(raw)
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise ValueError("expected 1–256 workload grants")
    grants = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"token_sha256", "agent_id", "session_id"}:
            raise ValueError("invalid workload grant fields")
        digest, agent, session = (entry[key] for key in ("token_sha256", "agent_id", "session_id"))
        if not all(isinstance(value, str) for value in (digest, agent, session)):
            raise ValueError("invalid workload grant values")
        if not _DIGEST.fullmatch(digest) or digest in grants:
            raise ValueError("invalid or duplicate workload credential digest")
        if not _IDENTIFIER.fullmatch(agent) or not _IDENTIFIER.fullmatch(session):
            raise ValueError("invalid workload agent or session identifier")
        grants[digest] = (agent, session)
    return grants


def _check_revocation(
    *, dashboard_url: str | None, event_token: str | None, module: str, tenant: str,
    agent: str, session: str, allow_insecure_dashboard: bool,
) -> None:
    try:
        endpoint = revocation_poll_url(dashboard_url or "")
        if not endpoint or not credential_transport_is_trusted(
            endpoint, allow_insecure=allow_insecure_dashboard,
        ) or not event_token or not _valid_bearer_token(event_token):
            raise ValueError("invalid revocation configuration")
        query = urllib.parse.urlencode({"agent_id": agent, "session_id": session})
        request = urllib.request.Request(f"{endpoint}?{query}", headers={
            "Authorization": f"Bearer {event_token}",
            TENANT_HEADER: tenant,
            "X-Monolith-Module": module,
        })
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        with opener.open(request, timeout=2) as response:
            result = json.loads(response.read(1024))
        if not isinstance(result, dict) or type(result.get("revoked")) is not bool:
            raise ValueError("invalid revocation response")
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise WorkloadDenied(503, "workload authorization is unavailable") from error
    if result["revoked"]:
        raise WorkloadDenied(403, "workload session is revoked")


def authorize_workload(
    headers: Mapping[str, str], *, tenant: str, module: str,
    dashboard_url: str | None, event_token: str | None, allow_insecure_dashboard: bool,
) -> EventContext:
    """Resolve a credential to a fixed identity and check live revocation."""
    raw = os.environ.get("MONOLITH_WORKLOAD_GRANTS_JSON")
    if raw is None:
        return context_from_headers(headers)
    try:
        grants = _grants(raw)
        if not _IDENTIFIER.fullmatch(tenant):
            raise ValueError("invalid workload tenant")
    except ValueError as error:
        raise WorkloadDenied(503, "workload authorization is unavailable") from error

    token = headers.get(WORKLOAD_HEADER, "")
    if len(token) < 32 or not _valid_bearer_token(token):
        raise WorkloadDenied(401, "invalid workload credential")
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    identity = None
    for registered, grant in grants.items():
        if compare_digest(digest, registered):
            identity = grant
    if identity is None:
        raise WorkloadDenied(401, "invalid workload credential")

    agent, session = identity
    for key, expected in ((TENANT_HEADER, tenant), (AGENT_HEADER, agent), (SESSION_HEADER, session)):
        if key in headers and headers[key] != expected:
            raise WorkloadDenied(403, "workload identity does not match its grant")
    _check_revocation(
        dashboard_url=dashboard_url, event_token=event_token, module=module, tenant=tenant,
        agent=agent, session=session, allow_insecure_dashboard=allow_insecure_dashboard,
    )
    return replace(
        context_from_headers(headers), tenant_id=tenant, agent_id=agent,
        session_id=session, workload_authenticated=True,
    )
