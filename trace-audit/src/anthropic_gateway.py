"""Anthropic-compatible streaming gateway for TraceAudit.

Claude Code — and every other Anthropic Messages API client — speaks
``POST /v1/messages`` and expects a Server-Sent Events answer. This module is
the wire-compatible front door for that traffic: the request is forwarded
upstream unchanged, and every fragment of the answer is piped through
TraceAudit's auditor before the client is allowed to see it.

Two things make that more than a pass-through:

* A credential or personal datum the model emits is redacted on the way out.
  It is the same bounded look-behind the internal endpoints use, so a secret
  split across two fragments is still caught whole.
* The client's own credential is forwarded upstream untouched. The gateway
  never stores it and never logs it, so it can sit in front of an ordinary
  Anthropic client without anyone having to hand the gateway a key.

The wire format is preserved exactly: the same event names, the same JSON
payloads, the same ordering. A client that cannot tell the difference is the
whole point — the defense has to be invisible to the agent it protects.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx

from .config import Config
from .events import EventContext
from .pii_scanner import scan
from .redaction import redact
from .stream_proxy import (
    FLUSH,
    POLICY_VERSION,
    SAFE_REFUSAL,
    StreamAuditor,
    secret_fingerprint,
)

# A single SSE line larger than this is a malformed (or hostile) upstream.
MAX_SSE_LINE_BYTES = 256 * 1024
# Guard against an upstream that never terminates its stream.
MAX_SSE_EVENTS = 1_000_000
ANTHROPIC_VERSION = "2023-06-01"
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 300.0
WRITE_TIMEOUT_SECONDS = 30.0
POOL_TIMEOUT_SECONDS = 5.0

# Delta kinds whose payload is model-authored text and therefore auditable.
# Tool arguments are included deliberately: a model that pastes a credential
# into a tool call has leaked it just as surely as one that writes it into
# prose. Redacting it may leave that tool call unparseable, which is the
# intended failure direction — fail closed rather than hand the secret on.
# Extended thinking is audited for the same reason: it is model-authored
# text, and it is text the client would otherwise read.
AUDITED_DELTA_KINDS = ("text_delta", "input_json_delta", "thinking_delta")

# The field each delta kind carries its payload in. An audited delta is
# re-framed for the client, and its kind has to survive that trip: a
# tool_use block's arguments delivered as a text_delta is a tool call the
# client cannot parse, and a thinking block's prose delivered as a text_delta
# is prose the client attributes to the answer instead of to the reasoning.
DELTA_PAYLOAD_FIELD = {
    "text_delta": "text",
    "input_json_delta": "partial_json",
    "thinking_delta": "thinking",
}

# A citation delta carries the passage the model quoted, inside a nested
# object rather than in a string field, so it cannot be audited by the same
# rule as the delta kinds above. It is still model-authored text and it
# still reaches the client, so it is audited on its own.
CITATION_DELTA_KIND = "citations_delta"

# The reason the auditor gives when it cut a stream short because the
# reasoning diverged. Any other reason is a transport failure, and the two
# must not be reported the same way: one is the defense working, the other
# is an answer the client must not mistake for a complete one.
DIVERGENCE_REASON = "reasoning_divergence"

# What a client is told when the upstream broke rather than refused. It is
# deliberately not the divergence refusal: telling an agent that its
# reasoning diverged when the connection dropped sends it looking for an
# attack that never happened.
UPSTREAM_FAILURE_REFUSAL = (
    "[TraceAudit] Response terminated: the model stream ended before the "
    "answer was complete. No answer was produced."
)


class UpstreamStreamError(RuntimeError):
    """The upstream stream ended in a failure rather than an answer."""


def _delta_text(delta: dict[str, Any]) -> str:
    """The model-authored payload of one delta, whatever kind it is."""
    field = DELTA_PAYLOAD_FIELD.get(str(delta.get("type")), "text")
    value = delta.get(field)
    return value if isinstance(value, str) else ""


def _sse_event_name(data: dict[str, Any], fallback: str) -> str:
    name = data.get("type")
    return name if isinstance(name, str) and name else fallback


async def iter_sse_events(lines: AsyncIterator[str]) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Parse a Server-Sent Events stream into (event name, JSON payload)."""
    event_name = ""
    data_lines: list[str] = []
    seen = 0
    async for raw in lines:
        seen += 1
        if seen > MAX_SSE_EVENTS:
            raise ValueError("upstream SSE stream exceeded the event limit")
        if len(raw.encode("utf-8", errors="replace")) > MAX_SSE_LINE_BYTES:
            raise ValueError("upstream SSE line exceeds 256 KiB")
        line = raw.rstrip("\r")
        if not line:
            if data_lines:
                payload = "\n".join(data_lines)
                data_lines = []
                name = event_name
                event_name = ""
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise ValueError("upstream SSE payload is not valid JSON") from exc
                if not isinstance(data, dict):
                    raise ValueError("upstream SSE payload must be a JSON object")
                yield _sse_event_name(data, name), data
            else:
                event_name = ""
            continue
        if line.startswith(":"):
            # A comment / keep-alive.
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)
    if data_lines:
        try:
            data = json.loads("\n".join(data_lines))
        except json.JSONDecodeError as exc:
            raise ValueError("upstream SSE payload is not valid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("upstream SSE payload must be a JSON object")
        yield _sse_event_name(data, event_name), data


class _QueuedEvent:
    """An upstream event waiting for the text that preceded it."""

    __slots__ = ("name", "data", "pushes_before")

    def __init__(self, name: str, data: dict[str, Any], pushes_before: int):
        self.name = name
        self.data = data
        self.pushes_before = pushes_before


class AnthropicRelay:
    """Pipes one upstream Anthropic answer through the auditor.

    The awkward part of auditing a framed protocol is ordering: the client
    must receive a block's text between that block's ``content_block_start``
    and its ``content_block_stop``, and the look-behind buffer holds text
    back, so the text is not ready when the block opens. The relay solves it
    with one rule — *an upstream event may be released once every text
    fragment that preceded it has been released* — and a single ordered
    queue that tracks how many fragments had been read when each event
    arrived.
    """

    def __init__(
        self,
        auditor: StreamAuditor,
        ctx: EventContext | None,
        *,
        divergence_enabled: bool,
        literals: Sequence[str] = (),
    ):
        self.auditor = auditor
        self.ctx = ctx
        self.divergence_enabled = divergence_enabled
        # Credentials this request carried. They are redacted from the answer
        # on the way out, whatever shape they have: the openai-style pattern
        # stops at the first hyphen, so an Anthropic key would pass through
        # it untouched.
        self._literals = tuple(literals)
        # One-way fingerprints of the credentials already reported in this
        # answer. Shared with the auditor, so a credential that appears both
        # in the prose and in a quoted passage is reported once.
        self._reported_secrets: set[bytes] = set()
        # push index -> the content block that push belonged to
        self._block_of_push: list[int] = []
        # push index -> the delta kind that push arrived as
        self._delta_kind_of_push: list[str] = []
        # upstream events still waiting for the text before them
        self._queue: list[_QueuedEvent] = []
        # how many text fragments have been pushed so far
        self._pushes = 0
        # how many of them have been fully released
        self._released_pushes = 0
        self._open_blocks: list[int] = []
        self._block_kind: dict[int, str] = {}
        # The content blocks the client has actually been told about. A
        # refusal has to open a block the client has not seen closed:
        # re-opening one is a malformed stream, and a malformed stream is
        # a transport failure the agent retries.
        self._client_blocks: set[int] = set()
        # Every complete answer ends with message_stop. A stream that ends
        # without one was cut short.
        self._saw_message_stop = False
        self._redactions: list[str] = []
        self._terminated = False
        self._stop_reason = "end_turn"
        # True when the upstream ended the answer without the message_stop
        # every complete answer carries. It is tracked separately from the
        # stop reason because the caller has to record the truncation in the
        # ledger, and "the stream was cut short" is not the same fact as
        # "the auditor refused".
        self._truncated = False
        self._usage: dict[str, Any] = {}

    # — upstream side ---------------------------------------------------

    async def _source(self, upstream: AsyncIterator[tuple[str, dict[str, Any]]]) -> AsyncIterator:
        """Turn the upstream SSE stream into auditable text fragments.

        Every upstream event is queued in order. Text fragments are pushed
        into the auditor, and a block boundary asks the auditor to release
        its look-behind so the block's text can be delivered before the
        block is closed.
        """
        async for name, data in upstream:
            kind = data.get("type") or name
            if kind == "message_stop":
                self._saw_message_stop = True
            elif kind == "content_block_start":
                index = data.get("index")
                if isinstance(index, int):
                    self._open_blocks.append(index)
                    block = data.get("content_block")
                    block_type = block.get("type") if isinstance(block, dict) else None
                    self._block_kind[index] = block_type if isinstance(block_type, str) else "text"
            elif kind == "content_block_delta":
                delta = data.get("delta")
                if isinstance(delta, dict) and delta.get("type") in AUDITED_DELTA_KINDS:
                    text = _delta_text(delta)
                    index = data.get("index")
                    block_index = index if isinstance(index, int) else 0
                    if text:
                        self._block_of_push.append(block_index)
                        self._delta_kind_of_push.append(str(delta.get("type")))
                        self._pushes += 1
                        yield text
                    continue
                if isinstance(delta, dict) and delta.get("type") == CITATION_DELTA_KIND:
                    self._audit_citation(data)
            elif kind == "content_block_stop":
                index = data.get("index")
                if isinstance(index, int) and index in self._open_blocks:
                    self._open_blocks.remove(index)
                self._queue.append(_QueuedEvent(name, data, self._pushes))
                # The block is closed: release the held-back text now, so the
                # client sees the block's content before its stop event.
                yield FLUSH
                continue
            self._queue.append(_QueuedEvent(name, data, self._pushes))
        # A final flush so the tail of the answer is delivered before the
        # closing events.
        yield FLUSH

    def _release_ready(self, through: int) -> list[_QueuedEvent]:
        ready: list[_QueuedEvent] = []
        while self._queue and self._queue[0].pushes_before <= through:
            ready.append(self._queue.pop(0))
        return ready

    def _audit_citation(self, data: dict[str, Any]) -> None:
        """Redact the passage a citation quotes, in place.

        A citation delta is not one of the audited delta kinds because its
        payload is not a string field: the quoted passage sits inside a
        nested ``citation`` object, alongside the document title and the
        character offsets. It is still text the model put in the answer,
        and it still reaches the client, so leaving it alone would have been
        the one place in the answer path where model-authored text was not
        scanned.

        The delta is rewritten rather than dropped, so the citation keeps
        its shape: the client reads the same citation with the credential
        replaced by a placeholder.
        """
        delta = data.get("delta")
        citation = delta.get("citation") if isinstance(delta, dict) else None
        if not isinstance(citation, dict):
            return
        cited = citation.get("cited_text")
        if not isinstance(cited, str) or not cited:
            return
        matches = scan(cited, self._literals)
        if not matches:
            return
        citation["cited_text"] = redact(cited, matches)
        for match in matches:
            fingerprint = secret_fingerprint(match.value)
            if fingerprint in self._reported_secrets:
                continue
            self._reported_secrets.add(fingerprint)
            self._redactions.append(match.label)
            self.auditor.emit(
                "pii_redacted",
                "warning",
                {
                    "label": match.label,
                    "redacted_as": f"[REDACTED:{match.label}]",
                    "position_tokens": self._pushes,
                    "delta_kind": CITATION_DELTA_KIND,
                },
                self.ctx,
                resource_type="reasoning_trace",
                resource_id=self.ctx.trace_id if self.ctx else None,
                outcome="redacted",
                policy_version=POLICY_VERSION,
            )

    def _note_client_block(self, data: dict[str, Any]) -> None:
        """Remember a content block the client has been told about."""
        if data.get("type") == "content_block_start":
            index = data.get("index")
            if isinstance(index, int):
                self._client_blocks.add(index)

    # — client side -----------------------------------------------------

    async def run(self, upstream: AsyncIterator[tuple[str, dict[str, Any]]]) -> AsyncIterator[dict]:
        """Yield the client's view of the answer, event by event.

        Each yielded dict is one of:

          {"kind": "passthrough", "event": <name>, "data": {...}}
          {"kind": "text", "index": <block>, "text": <fragment>}
          {"kind": "terminated", "reason": <str>}
          {"kind": "done"}
        """
        source = self._source(upstream)
        audit = self.auditor.audit_tokens(
            source,
            self.ctx,
            divergence_enabled=self.divergence_enabled,
            emit_sync=True,
            literals=self._literals,
            reported_secrets=self._reported_secrets,
        )
        async for evt in audit:
            kind = evt.get("type")
            if kind == "token":
                index = self._block_of_push[evt["source_index"]] if evt["source_index"] >= 0 else 0
                # The kind the fragment arrived as travels with it: the client
                # has to be able to tell a tool call's arguments from prose.
                delta_kind = (
                    self._delta_kind_of_push[evt["source_index"]]
                    if 0 <= evt["source_index"] < len(self._delta_kind_of_push)
                    else "text_delta"
                )
                # Anything read before this fragment has to reach the client
                # first, or the block's start event would follow its text.
                for queued in self._release_ready(evt["source_index"]):
                    self._note_client_block(queued.data)
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
                yield {
                    "kind": "text",
                    "index": index,
                    "text": evt["token"],
                    "delta_kind": delta_kind,
                }
            elif kind == "pii":
                self._redactions.append(evt["label"])
            elif kind == "sync":
                for queued in self._release_ready(self._released_pushes):
                    self._note_client_block(queued.data)
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
            elif kind == "flush":
                # Everything pushed so far is out of the buffer.
                self._released_pushes = self._pushes
                for queued in self._release_ready(self._released_pushes):
                    self._note_client_block(queued.data)
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
            elif kind == "terminated":
                # The queued events are released first, for the same reason
                # the error path releases them. The divergence fires in the
                # middle of an answer, so the block that was open when it
                # fired is still open on the client — and the block's stop
                # event is sitting in the queue, waiting for the text before
                # it to be released. Releasing the queue hands the client
                # the stop it is owed; not releasing it leaves the client
                # holding a block it never saw the end of, and the refusal
                # then opens a second block for an answer the client cannot
                # assemble.
                for queued in self._release_ready(self._pushes):
                    self._note_client_block(queued.data)
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
                self._terminated = True
                self._stop_reason = "refusal"
                yield {"kind": "terminated", "reason": evt.get("reason", "terminated")}
                return
            elif kind == "error":
                # The auditor failed mid-answer. The queued events are
                # released first, for the same reason the truncation path
                # releases them: a client that has been told about a content
                # block must be told the block closed before the refusal
                # opens another one, or it is left holding a block it never
                # saw the end of.
                for queued in self._release_ready(self._pushes):
                    self._note_client_block(queued.data)
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
                self._terminated = True
                self._stop_reason = "upstream_error"
                yield {"kind": "terminated", "reason": evt.get("error", "upstream_stream_error")}
                return
        if not self._saw_message_stop:
            # The upstream ended the stream without the message_stop that
            # every complete answer carries, so the answer is truncated. A
            # truncated answer handed over as a complete one is worse than
            # an error: the agent would act on it and never learn that it
            # was cut short.
            #
            # The queued events are released first. The block the client
            # was given has to be closed before the refusal, or the client
            # is left with a block it never saw the end of, and the
            # refusal's own block would reopen an index the client has
            # already seen finished.
            for queued in self._release_ready(self._pushes):
                self._note_client_block(queued.data)
                yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
            self._terminated = True
            self._stop_reason = "upstream_error"
            self._truncated = True
            yield {"kind": "terminated", "reason": "upstream_stream_error"}
            return
        for queued in self._release_ready(self._pushes):
            self._note_client_block(queued.data)
            yield {"kind": "passthrough", "event": queued.name, "data": queued.data}

    def refusal_events(self, reason: str) -> list[dict]:
        """The client-visible shape of a refused answer.

        A refusal has to be a *well-formed* message: an agent that receives a
        malformed response treats it as a transport failure and retries,
        which is exactly the wrong reaction to a session the circuit breaker
        has already revoked.

        Well-formed means the content blocks line up. A block the client has
        already seen closed is never re-opened under the same index — that
        is a second ``content_block_start`` for one block, and a client that
        tracks blocks by index reads the refusal as a continuation of an
        answer that was already closed. A block the client has not seen
        opened is opened first, so the refusal text never arrives for a
        block that was never announced.
        """
        refusal = (
            SAFE_REFUSAL
            if reason == DIVERGENCE_REASON
            else UPSTREAM_FAILURE_REFUSAL
        )
        events: list[dict] = []

        def _start(index: int) -> dict[str, Any]:
            self._client_blocks.add(index)
            return {
                "kind": "passthrough",
                "event": "content_block_start",
                "data": {
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {"type": "text", "text": ""},
                },
            }

        if self._open_blocks:
            index = self._open_blocks[-1]
            if index not in self._client_blocks:
                # The block was announced upstream but the announcement never
                # reached the client: it is still queued behind the
                # fragments that were discarded. Open it now.
                events.append(_start(index))
            events.append(
                {
                    "kind": "text",
                    "index": index,
                    "text": refusal,
                }
            )
            for open_index in list(self._open_blocks):
                events.append(
                    {
                        "kind": "passthrough",
                        "event": "content_block_stop",
                        "data": {"type": "content_block_stop", "index": open_index},
                    }
                )
            self._open_blocks.clear()
        else:
            # Every block the client knows about is closed, so the refusal
            # opens a new one rather than reusing a finished index.
            index = max(self._client_blocks) + 1 if self._client_blocks else 0
            events.append(_start(index))
            events.append({"kind": "text", "index": index, "text": refusal})
            events.append(
                {
                    "kind": "passthrough",
                    "event": "content_block_stop",
                    "data": {"type": "content_block_stop", "index": index},
                }
            )
        events.append(
            {
                "kind": "passthrough",
                "event": "message_delta",
                "data": {
                    "type": "message_delta",
                    "delta": {"stop_reason": "refusal", "stop_sequence": None},
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            }
        )
        events.append(
            {
                "kind": "passthrough",
                "event": "message_stop",
                "data": {"type": "message_stop"},
            }
        )
        return events

    def summary(self) -> dict[str, Any]:
        return {
            "terminated": self._terminated,
            "stop_reason": self._stop_reason,
            # True when the upstream ended the answer without the
            # message_stop every complete answer carries. The caller
            # records it: an answer that was cut short has to be in the
            # ledger, or the run reads as a clean one.
            "truncated": self._truncated,
            "redactions": list(self._redactions),
            "redaction_count": len(self._redactions),
            "blocks": len(self._block_kind),
        }


def format_sse(event: dict) -> str:
    """Render one client-visible event as a Server-Sent Events frame."""
    kind = event.get("kind")
    if kind == "passthrough":
        name = event["event"]
        data = event["data"]
    elif kind == "text":
        name = "content_block_delta"
        delta_kind = event.get("delta_kind") or "text_delta"
        field = DELTA_PAYLOAD_FIELD.get(delta_kind, "text")
        data = {
            "type": "content_block_delta",
            "index": event["index"],
            "delta": {"type": delta_kind, field: event["text"]},
        }
    else:
        raise ValueError(f"cannot serialize event kind {kind!r}")
    return f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


def build_upstream_request(
    body: bytes,
    cfg: Config,
    headers_in: dict[str, str],
) -> tuple[str, dict[str, str], bytes]:
    """Build the upstream request from the client's request.

    The body is forwarded byte-for-byte: the gateway is a security control,
    not a translator, and re-serializing the payload would quietly change
    what the model is asked to do. The three mutations the gateway is
    allowed to make — always stream, the operator's pinned model, and the
    operator's token ceiling — are made by the caller, so the bytes that
    arrive here already carry them.
    """
    base = cfg.anthropic_base_url.rstrip("/")
    # The operator may configure the API root ("https://api.anthropic.com"),
    # the versioned root (".../v1") or the endpoint itself. All three name
    # the same endpoint, and appending blindly to a base that already ends
    # in /v1 asks for /v1/v1/messages, so every audited call 404s.
    if base.endswith("/v1/messages"):
        url = base
    elif base.endswith("/v1"):
        url = base + "/messages"
    else:
        url = base + "/v1/messages"
    headers = {
        "content-type": "application/json",
        "accept": "text/event-stream",
        "anthropic-version": headers_in.get("anthropic-version") or ANTHROPIC_VERSION,
    }
    beta = headers_in.get("anthropic-beta")
    if beta:
        headers["anthropic-beta"] = beta
    # The client's own credential wins: the gateway is transparent about who
    # is paying. The configured key is the fallback for clients that have
    # none of their own.
    client_key = headers_in.get("x-api-key")
    client_auth = headers_in.get("authorization")
    if client_key:
        headers["x-api-key"] = client_key
    if client_auth:
        headers["authorization"] = client_auth
    if not client_key and not client_auth and cfg.anthropic_api_key:
        headers["x-api-key"] = cfg.anthropic_api_key
    return url, headers, body


def upstream_timeout() -> httpx.Timeout:
    return httpx.Timeout(
        connect=CONNECT_TIMEOUT_SECONDS,
        read=READ_TIMEOUT_SECONDS,
        write=WRITE_TIMEOUT_SECONDS,
        pool=POOL_TIMEOUT_SECONDS,
    )


def standalone_refusal_message(model: str, message_id: str) -> dict[str, Any]:
    """The same refusal as one JSON document.

    A client that asked for ``"stream": false`` expects a document. Handing
    it a server-sent event stream leaves it with a body it cannot parse,
    which it reads as a transport failure and retries — the wrong reaction
    to a session the circuit breaker has already revoked.
    """
    return {
        "id": message_id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": SAFE_REFUSAL}],
        "stop_reason": "refusal",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


def standalone_refusal_sse(model: str, message_id: str) -> str:
    """A complete, well-formed refusal for a request that never reached the
    model — a session the circuit breaker has revoked, for instance."""
    events: list[dict[str, Any]] = [
        {
            "kind": "passthrough",
            "event": "message_start",
            "data": {
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": model,
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            },
        },
        {
            "kind": "passthrough",
            "event": "content_block_start",
            "data": {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        },
        {"kind": "text", "index": 0, "text": SAFE_REFUSAL},
        {
            "kind": "passthrough",
            "event": "content_block_stop",
            "data": {"type": "content_block_stop", "index": 0},
        },
        {
            "kind": "passthrough",
            "event": "message_delta",
            "data": {
                "type": "message_delta",
                "delta": {"stop_reason": "refusal", "stop_sequence": None},
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        },
        {
            "kind": "passthrough",
            "event": "message_stop",
            "data": {"type": "message_stop"},
        },
    ]
    return "".join(format_sse(event) for event in events)


def relay_sse(
    relay: AnthropicRelay,
    response: httpx.Response,
) -> AsyncIterator[str]:
    """Turn the relay's structured events into the client's SSE stream."""
    return _relay_sse(relay, response)


async def _relay_sse(
    relay: AnthropicRelay,
    response: httpx.Response,
) -> AsyncIterator[str]:
    upstream = iter_sse_events(response.aiter_lines())
    async for event in relay.run(upstream):
        if event.get("kind") == "terminated":
            for refusal in relay.refusal_events(event.get("reason", "terminated")):
                yield format_sse(refusal)
            return
        yield format_sse(event)


async def collect_message(
    relay: AnthropicRelay,
    upstream: AsyncIterator[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    """Assemble a non-streaming Anthropic message from the audited stream.

    A client that asked for ``"stream": false`` expects one JSON document,
    not a sequence of events. The audited text is the same either way — only
    the framing differs.
    """
    message: dict[str, Any] = {}
    blocks: dict[int, dict[str, Any]] = {}
    order: list[int] = []
    refused = False

    def _block(index: int, kind: str) -> dict[str, Any]:
        if index not in blocks:
            blocks[index] = {
                "type": kind,
                "text": "",
                "partial_json": "",
                "thinking": "",
                "signature": "",
            }
            order.append(index)
        return blocks[index]

    async for event in relay.run(upstream):
        kind = event.get("kind")
        if kind == "terminated":
            reason = event.get("reason", "terminated")
            if reason == DIVERGENCE_REASON:
                # The defense worked: the answer is refused. Anything the
                # model said before the divergence is dropped, because a
                # partial answer is not an answer.
                refused = True
                break
            # The upstream broke mid-answer. Handing the client a partial
            # answer as a complete one is worse than an error: the agent
            # would act on it.
            raise UpstreamStreamError(reason)
        if kind == "passthrough":
            etype = event["data"].get("type")
            if etype == "message_start":
                raw_message = event["data"].get("message")
                if isinstance(raw_message, dict):
                    message = dict(raw_message)
            elif etype == "content_block_start":
                index = event["data"].get("index")
                block = event["data"].get("content_block")
                block_type = "text"
                block_id = ""
                block_name = ""
                if isinstance(block, dict):
                    if isinstance(block.get("type"), str):
                        block_type = block["type"]
                    if isinstance(block.get("id"), str):
                        block_id = block["id"]
                    if isinstance(block.get("name"), str):
                        block_name = block["name"]
                if isinstance(index, int):
                    entry = _block(index, block_type)
                    entry["id"] = block_id
                    entry["name"] = block_name
            elif etype == "content_block_delta":
                # The signature of a thinking block arrives in its own delta
                # and is not model-authored text, so it is passed through
                # unexamined — but it still has to reach the client.
                delta = event["data"].get("delta")
                index = event["data"].get("index")
                if (
                    isinstance(delta, dict)
                    and delta.get("type") == "signature_delta"
                    and isinstance(index, int)
                ):
                    signature = delta.get("signature")
                    if isinstance(signature, str):
                        _block(index, "thinking")["signature"] = signature
            elif etype == "message_delta":
                delta = event["data"].get("delta")
                if isinstance(delta, dict) and delta.get("stop_reason"):
                    message["stop_reason"] = delta["stop_reason"]
                usage = event["data"].get("usage")
                if isinstance(usage, dict):
                    merged = dict(message.get("usage") or {})
                    merged.update(usage)
                    message["usage"] = merged
        elif kind == "text":
            index = event["index"]
            delta_kind = event.get("delta_kind") or "text_delta"
            field = DELTA_PAYLOAD_FIELD.get(delta_kind, "text")
            block = _block(index, "text")
            block[field] += event["text"]

    content: list[dict[str, Any]] = []
    if refused:
        content.append({"type": "text", "text": SAFE_REFUSAL})
        message["stop_reason"] = "refusal"
    else:
        for index in order:
            block = blocks[index]
            if block["type"] == "text":
                content.append({"type": "text", "text": block["text"]})
            elif block["type"] == "thinking":
                content.append(
                    {
                        "type": "thinking",
                        "thinking": block["thinking"],
                        "signature": block["signature"],
                    }
                )
            else:
                # A tool-use block. Its arguments arrived as JSON fragments;
                # a redaction may have made them unparseable, and an
                # unparseable argument set is a fail-closed answer, not a
                # leak.
                raw = block["partial_json"].strip()
                try:
                    parsed = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    parsed = {}
                content.append(
                    {
                        "type": block["type"],
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "input": parsed,
                    }
                )
    message["content"] = content
    message.setdefault("type", "message")
    message.setdefault("role", "assistant")
    message.setdefault("stop_reason", "end_turn")
    message.setdefault("stop_sequence", None)
    return message


__all__ = [
    "ANTHROPIC_VERSION",
    "AnthropicRelay",
    "DIVERGENCE_REASON",
    "POLICY_VERSION",
    "UpstreamStreamError",
    "build_upstream_request",
    "collect_message",
    "format_sse",
    "iter_sse_events",
    "relay_sse",
    "standalone_refusal_message",
    "standalone_refusal_sse",
    "upstream_timeout",
]
