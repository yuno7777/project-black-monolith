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
from collections.abc import AsyncIterator
from typing import Any

import httpx

from .config import Config
from .events import EventContext
from .stream_proxy import FLUSH, POLICY_VERSION, SAFE_REFUSAL, StreamAuditor

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
AUDITED_DELTA_KINDS = ("text_delta", "input_json_delta")


def _delta_text(delta: dict[str, Any]) -> str:
    for field in ("text", "partial_json"):
        value = delta.get(field)
        if isinstance(value, str) and value:
            return value
    return ""


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
    ):
        self.auditor = auditor
        self.ctx = ctx
        self.divergence_enabled = divergence_enabled
        # push index -> the content block that push belonged to
        self._block_of_push: list[int] = []
        # upstream events still waiting for the text before them
        self._queue: list[_QueuedEvent] = []
        # how many text fragments have been pushed so far
        self._pushes = 0
        # how many of them have been fully released
        self._released_pushes = 0
        self._open_blocks: list[int] = []
        self._block_kind: dict[int, str] = {}
        self._redactions: list[str] = []
        self._terminated = False
        self._stop_reason = "end_turn"
        self._usage: dict[str, Any] = {}

    # -- upstream side ---------------------------------------------------

    async def _source(self, upstream: AsyncIterator[tuple[str, dict[str, Any]]]) -> AsyncIterator:
        """Turn the upstream SSE stream into auditable text fragments.

        Every upstream event is queued in order. Text fragments are pushed
        into the auditor, and a block boundary asks the auditor to release
        its look-behind so the block's text can be delivered before the
        block is closed.
        """
        async for name, data in upstream:
            kind = data.get("type") or name
            if kind == "content_block_start":
                index = data.get("index")
                if isinstance(index, int):
                    self._open_blocks.append(index)
                    block = data.get("content_block")
                    self._block_kind[index] = (
                        block.get("type") if isinstance(block, dict) and isinstance(block.get("type"), str) else "text"
                    )
            elif kind == "content_block_delta":
                delta = data.get("delta")
                if isinstance(delta, dict) and delta.get("type") in AUDITED_DELTA_KINDS:
                    text = _delta_text(delta)
                    index = data.get("index")
                    block_index = index if isinstance(index, int) else 0
                    if text:
                        self._block_of_push.append(block_index)
                        self._pushes += 1
                        yield text
                    continue
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

    # -- client side -----------------------------------------------------

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
        )
        async for evt in audit:
            kind = evt.get("type")
            if kind == "token":
                index = self._block_of_push[evt["source_index"]] if evt["source_index"] >= 0 else 0
                # Anything read before this fragment has to reach the client
                # first, or the block's start event would follow its text.
                for queued in self._release_ready(evt["source_index"]):
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
                yield {"kind": "text", "index": index, "text": evt["token"]}
            elif kind == "pii":
                self._redactions.append(evt["label"])
            elif kind == "sync":
                for queued in self._release_ready(self._released_pushes):
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
            elif kind == "flush":
                # Everything pushed so far is out of the buffer.
                self._released_pushes = self._pushes
                for queued in self._release_ready(self._released_pushes):
                    yield {"kind": "passthrough", "event": queued.name, "data": queued.data}
            elif kind == "terminated":
                self._terminated = True
                self._stop_reason = "refusal"
                yield {"kind": "terminated", "reason": evt.get("reason", "terminated")}
                return
            elif kind == "error":
                self._terminated = True
                yield {"kind": "terminated", "reason": evt.get("error", "upstream_stream_error")}
                return
        for queued in self._release_ready(self._pushes):
            yield {"kind": "passthrough", "event": queued.name, "data": queued.data}

    def refusal_events(self, reason: str) -> list[dict]:
        """The client-visible shape of a refused answer.

        A refusal has to be a *well-formed* message: an agent that receives a
        malformed response treats it as a transport failure and retries,
        which is exactly the wrong reaction to a session the circuit breaker
        has already revoked.
        """
        events: list[dict] = []
        if self._open_blocks:
            index = self._open_blocks[-1]
            events.append(
                {
                    "kind": "text",
                    "index": index,
                    "text": SAFE_REFUSAL,
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
            events.append(
                {
                    "kind": "passthrough",
                    "event": "content_block_start",
                    "data": {
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": ""},
                    },
                }
            )
            events.append({"kind": "text", "index": 0, "text": SAFE_REFUSAL})
            events.append(
                {
                    "kind": "passthrough",
                    "event": "content_block_stop",
                    "data": {"type": "content_block_stop", "index": 0},
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
        data = {
            "type": "content_block_delta",
            "index": event["index"],
            "delta": {"type": "text_delta", "text": event["text"]},
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
    what the model is asked to do.
    """
    base = cfg.anthropic_base_url.rstrip("/")
    url = base if base.endswith("/v1/messages") else base + "/v1/messages"
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


def standalone_refusal_sse(model: str, message_id: str) -> str:
    """A complete, well-formed refusal for a request that never reached the
    model — a session the circuit breaker has revoked, for instance."""
    events = [
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

    def _block(index: int, kind: str) -> dict[str, Any]:
        if index not in blocks:
            blocks[index] = {"type": kind, "text": ""}
            order.append(index)
        return blocks[index]

    async for event in relay.run(upstream):
        kind = event.get("kind")
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
            block = _block(index, "text")
            block["text"] += event["text"]

    content: list[dict[str, Any]] = []
    for index in order:
        block = blocks[index]
        if block["type"] == "text":
            content.append({"type": "text", "text": block["text"]})
        else:
            # A tool-use block. Its arguments arrived as JSON fragments; a
            # redaction may have made them unparseable, and an unparseable
            # argument set is a fail-closed answer, not a leak.
            raw = block["text"].strip()
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
    message.setdefault("stop_reason", "end_turn")
    message.setdefault("stop_sequence", None)
    return message


__all__ = [
    "ANTHROPIC_VERSION",
    "AnthropicRelay",
    "POLICY_VERSION",
    "build_upstream_request",
    "collect_message",
    "format_sse",
    "iter_sse_events",
    "relay_sse",
    "standalone_refusal_sse",
    "upstream_timeout",
]
