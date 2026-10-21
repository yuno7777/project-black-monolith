#!/usr/bin/env python3
"""VectorAnchor as an MCP server, over stdio.

This is the memory layer's door into an agent. An MCP client (Claude Code,
or anything else that speaks MCP) starts this as a child process and calls
``retrieve``; the retrieval itself is served by the running VectorAnchor
service, so the poisoned-document detector, the quarantine list and the
corpus all stay in one place.

Two deliberate choices:

* **It is a bridge, not a second copy of the service.** The FastAPI service
  owns the single ChromaDB client; a second ``PersistentClient`` on the same
  path contends on ChromaDB's SQLite store. Talking to the service over
  HTTP keeps exactly one owner of the corpus and of the detector state.
* **It is standard library only.** The process is started by the agent's
  host, not by the container, and it has to run wherever the agent runs —
  with no virtualenv to prepare. The service it calls carries the heavy
  dependencies.

Correlation: the session, agent and tenant ids come from the environment,
which is how the launcher that wraps an agent session stamps them. Every
retrieval is therefore attributed to the same session as the tool calls and
the model traffic around it, which is what makes the cross-layer circuit
breaker able to see them together.

Environment:

  MONOLITH_VECTOR_ANCHOR_URL   service base URL (default http://127.0.0.1:8001)
  MONOLITH_TENANT_ID           tenant the session belongs to
  MONOLITH_AGENT_ID            the agent
  MONOLITH_SESSION_ID          the session (required)
  MONOLITH_REQUEST_TIMEOUT_S   per-request timeout (default 15)

``MONOLITH_SESSION_ID`` is required, not optional. The cross-layer circuit
breaker revokes a session, so a retrieval that cannot be attributed to one is
a retrieval the breaker cannot protect; the service refuses those, and this
server says so rather than making the call and letting it fail downstream.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import traceback
import urllib.error
import urllib.request

SERVER_NAME = "vector-anchor"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
# The version the handshake falls back to when the client asks for one this
# server does not know. MCP says the server should answer with a version it
# supports, and should prefer the latest: a client that has dropped the
# oldest version but would happily have used the newest cannot connect to a
# server that answers with the oldest.
LATEST_PROTOCOL_VERSION = "2025-06-18"

MAX_QUERY_LENGTH = 16_384
MAX_K = 20

TOOL_SCHEMA = {
    "name": "retrieve",
    "description": (
        "Search the project knowledge base for passages relevant to a question. "
        "Documents that the corpus-poisoning detector has flagged are withheld "
        "before they reach you, and the result says how many were withheld, so "
        "a short answer is not necessarily a complete one."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The question or topic to look up.",
                "minLength": 1,
                "maxLength": MAX_QUERY_LENGTH,
            },
            "k": {
                "type": "integer",
                "description": (
                    "How many passages to return. Fewer than the default when "
                    "the answer only needs a couple of them."
                ),
                "minimum": 1,
                "maximum": MAX_K,
            },
        },
        "required": ["query"],
    },
}


def _log(message: str) -> None:
    """Everything but the protocol goes to stderr. stdout is the wire."""
    print(f"[vector-anchor-mcp] {message}", file=sys.stderr, flush=True)


def _send(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _error(request_id, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def _result(request_id, result: dict) -> None:
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _result_text(request_id, text: str, *, is_error: bool = False) -> None:
    _result(
        request_id,
        {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        },
    )


def _service_url() -> str:
    base = os.environ.get("MONOLITH_VECTOR_ANCHOR_URL", "http://127.0.0.1:8001").rstrip("/")
    return base


def _timeout_seconds() -> float:
    raw = os.environ.get("MONOLITH_REQUEST_TIMEOUT_S", "15")
    try:
        value = float(raw)
    except ValueError:
        return 15.0
    return value if value > 0 else 15.0


def _correlation_headers() -> dict[str, str]:
    headers = {"content-type": "application/json"}
    for env_name, header in (
        ("MONOLITH_TENANT_ID", "X-Monolith-Tenant-Id"),
        ("MONOLITH_AGENT_ID", "X-Monolith-Agent-Id"),
        ("MONOLITH_SESSION_ID", "X-Monolith-Session-Id"),
    ):
        value = (os.environ.get(env_name) or "").strip()
        if value:
            headers[header] = value
    return headers


def _error_detail(error: urllib.error.HTTPError) -> str:
    """Whatever the service managed to say about the failure.

    The body of an error response is read here, inside the handler, and
    reading it can fail: a service that stops mid-body raises
    ``IncompleteRead``, and one that drops the connection raises
    ``OSError``. An exception raised inside an ``except`` block is not
    caught by the sibling clauses of the same ``try``, so it would escape
    this function, escape the tool call, and take the server down
    mid-session — over a detail the agent does not need. The status code is
    the fact; the body is a nicety.
    """
    try:
        return error.read().decode("utf-8", errors="replace")[:400]
    except (OSError, http.client.HTTPException):
        return "(the response body could not be read)"


def _session_id() -> str:
    return (os.environ.get("MONOLITH_SESSION_ID") or "").strip()


def _call_service(payload: dict) -> dict:
    url = _service_url() + "/retrieve"
    try:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=_correlation_headers(),
            method="POST",
        )
    except ValueError as error:
        # A malformed URL is an operator error, not a network error, and it
        # is raised before the request is ever sent. Left unhandled it takes
        # the whole server down for a typo in an environment variable.
        raise RuntimeError(
            f"VectorAnchor URL is not usable: {url!r}. Set "
            "MONOLITH_VECTOR_ANCHOR_URL to an absolute http(s) URL."
        ) from error
    try:
        with urllib.request.urlopen(request, timeout=_timeout_seconds()) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"VectorAnchor returned HTTP {error.code}: {_error_detail(error)}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            f"VectorAnchor is unreachable at {_service_url()}: {error.reason}. "
            "Is the service running?"
        ) from error
    except (OSError, http.client.HTTPException) as error:
        # A read timeout or a connection reset is not a URLError: urllib
        # raises the builtin OSError, and an exception the caller does not
        # catch would take the whole server down mid-session, taking the
        # agent's retrieve tool with it.
        #
        # A truncated response is neither: http.client raises IncompleteRead
        # or BadStatusLine, and HTTPException is *not* an OSError, so it has
        # to be named explicitly or it escapes the same way.
        raise RuntimeError(
            f"VectorAnchor did not answer at {_service_url()}: {error}. "
            "Is the service running?"
        ) from error
    try:
        decoded = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        # A body that is not valid UTF-8 is not valid JSON either, but it
        # raises UnicodeDecodeError, and JSONDecodeError does not catch it.
        raise RuntimeError("VectorAnchor returned a response that is not JSON") from error
    if not isinstance(decoded, dict):
        raise RuntimeError("VectorAnchor returned a response that is not an object")
    return decoded


def _render(payload: dict) -> str:
    """The answer the agent reads.

    It says how many passages were withheld. An agent that can see that a
    document was filtered knows its context is incomplete, which is the
    difference between a defense the agent can work around and one it
    silently routes around.
    """
    results = payload.get("results")
    if not isinstance(results, list):
        results = []
    withheld = payload.get("withheld")
    if not isinstance(withheld, list):
        withheld = []

    if payload.get("session_quarantined"):
        return (
            "This session has been revoked by the corpus-poisoning circuit breaker, "
            "so nothing was retrieved."
        )

    lines: list[str] = []
    if not results:
        lines.append("No passages matched that query.")
    else:
        lines.append(f"{len(results)} passage(s) matched:")
        for position, item in enumerate(results, start=1):
            document = item.get("document") if isinstance(item, dict) else None
            identifier = item.get("id") if isinstance(item, dict) else None
            header = f"[{position}]"
            if identifier:
                header += f" {identifier}"
            lines.append(header)
            lines.append((document or "").strip())
            lines.append("")
    if withheld:
        lines.append(
            f"{len(withheld)} document(s) were withheld by the corpus-poisoning "
            "filter and are not shown here."
        )
    return "\n".join(lines).strip()


def _handle_call(request_id, params: dict) -> None:
    name = params.get("name")
    if name != TOOL_SCHEMA["name"]:
        _error(request_id, -32602, f"unknown tool: {name}")
        return
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip():
        _result_text(request_id, "The query must be a non-empty string.", is_error=True)
        return
    if len(query) > MAX_QUERY_LENGTH:
        _result_text(request_id, "The query is too long.", is_error=True)
        return
    if not _session_id():
        # A retrieval that cannot be attributed to a session is one the
        # cross-layer circuit breaker cannot revoke, so the service refuses
        # it. Saying so here is better than letting the call fail
        # downstream: a misconfiguration has to be loud, and the name of
        # the variable that is missing is what the operator needs.
        _result_text(
            request_id,
            "VectorAnchor cannot serve a retrieval without a session id. Set "
            "MONOLITH_SESSION_ID so the retrieval can be attributed to a "
            "session and revoked with it.",
            is_error=True,
        )
        return
    payload: dict = {"query": query}
    k = arguments.get("k")
    if isinstance(k, int) and not isinstance(k, bool) and 1 <= k <= MAX_K:
        payload["k"] = k
    try:
        response = _call_service(payload)
    except RuntimeError as error:
        _result_text(request_id, str(error), is_error=True)
        return
    except Exception as error:
        # The service is a network peer, and anything it does can surface
        # here as an exception the clause above does not name. An unhandled
        # one kills the server and takes the agent's retrieve tool with it —
        # a whole agent session loses its memory layer over one bad
        # response. The traceback goes to stderr, where an operator will
        # find it, and the agent is told the call failed rather than being
        # left waiting on an answer that will never come.
        #
        # Deliberately broad, and deliberately not `BaseException`: a
        # KeyboardInterrupt must still stop the server.
        _log(f"unexpected failure serving a retrieve call: {error!r}")
        traceback.print_exc(file=sys.stderr)
        _result_text(request_id, "VectorAnchor did not answer.", is_error=True)
        return
    # A revoked session is a refusal, not an answer. It has to say so on the
    # wire: an agent that reads a refusal as a successful retrieval of zero
    # documents has no reason to stop, and the next tool call it makes lands
    # in the same revoked session.
    _result_text(
        request_id,
        _render(response),
        is_error=bool(response.get("session_quarantined")),
    )


def main() -> int:
    _log(f"starting; service {_service_url()}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _error(None, -32700, "parse error")
            continue
        if not isinstance(message, dict):
            _error(None, -32600, "invalid request")
            continue
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params")
        if not isinstance(params, dict):
            params = {}

        if method == "initialize":
            if request_id is None:
                continue
            requested = params.get("protocolVersion")
            version = (
                requested
                if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
                else LATEST_PROTOCOL_VERSION
            )
            _result(
                request_id,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            )
        elif method in ("notifications/initialized", "initialized"):
            # A notification: no id, no response.
            continue
        elif method == "ping":
            if request_id is None:
                continue
            _result(request_id, {})
        elif method == "tools/list":
            if request_id is None:
                continue
            _result(request_id, {"tools": [TOOL_SCHEMA]})
        elif method == "tools/call":
            if request_id is None:
                continue
            _handle_call(request_id, params)
        elif request_id is not None:
            _error(request_id, -32601, f"method not found: {method}")
    _log("stdin closed; exiting")
    return 0


if __name__ == "__main__":
    sys.exit(main())
