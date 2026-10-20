#!/usr/bin/env python3
"""Local stand-in for the Anthropic Messages API.

TraceAudit's gateway is the front door for Anthropic traffic, so testing it
needs something that speaks the Messages API. This stub answers
``POST /v1/messages`` with a Server-Sent Events stream in the same shape the
real API uses: ``message_start``, ``content_block_start``, a run of
``content_block_delta`` events, ``content_block_stop``, ``message_delta`` and
``message_stop``.

It runs on localhost, makes no outbound connection, and holds no credential.
The "leaked" string it can emit is AWS's own published example key — a value
that exists in the AWS documentation precisely so that secret scanners
recognise it, and which is not a credential to anything.

Modes (env ``FAKE_ANTHROPIC_MODE``):

  clean    an ordinary multi-block answer
  secret   an answer that leaks the example key mid-stream
  tool     an answer that calls a tool, so the block ordering can be checked
  echo     an answer that repeats back the credential the request carried,
           so a test can check what the gateway does with a key that comes
           back inside a normal 200 answer

Run it directly:

    python fixtures/fake_anthropic_server.py --port 8100
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# AWS's documented example key. Published in the AWS docs so that scanners
# can recognise it; it is not a credential to anything.
FICTIONAL_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

ORDINARY = (
    "The gateway in front of a model has one job: be invisible. "
    "An agent should not be able to tell that its traffic was inspected, "
    "because an agent that can tell may start behaving differently, and the "
    "defense would then be measuring the workaround instead of the attack. "
    "So the event names, the ordering and the payload shapes all have to "
    "survive the round trip unchanged, and the only visible difference has "
    "to be the one the defense exists to make: a credential the model was "
    "about to hand over is not handed over. "
)

LEAKY = (
    "Sure, here is the configuration you asked for. The access key id is "
    + FICTIONAL_AWS_KEY
    + " and the region is eu-west-1. Keep that key out of version control. "
)

TOOL_CALL = {
    "name": "read_file",
    "input": {"path": "README.md"},
}

# The "echo" mode repeats a credential back inside an otherwise ordinary
# answer. A provider that has the key can put it anywhere in the text, and
# the answer it hands back is a 200, not an error.
ECHO_TEMPLATE = (
    "Sure, here is the credential you asked for: {key} "
    "and that is the only one I have."
)


def _message_start(model: str) -> dict:
    return {
        "type": "message_start",
        "message": {
            "id": f"msg_{uuid.uuid4().hex[:24]}",
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": model,
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {"input_tokens": 42, "output_tokens": 1},
        },
    }


def _frames(mode: str, model: str, echo_key: str = "") -> list[tuple[str, dict]]:
    """The event sequence the stub streams back, in order."""
    frames: list[tuple[str, dict]] = [("message_start", _message_start(model))]

    if mode == "tool":
        frames.append(
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            )
        )
        frames.append(
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "Let me look at that file."},
                },
            )
        )
        frames.append(
            (
                "content_block_stop",
                {"type": "content_block_stop", "index": 0},
            )
        )
        frames.append(
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 1,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu_01stub",
                        "name": TOOL_CALL["name"],
                        "input": {},
                    },
                },
            )
        )
        frames.append(
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 1,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": json.dumps(TOOL_CALL["input"]),
                    },
                },
            )
        )
        frames.append(
            (
                "content_block_stop",
                {"type": "content_block_stop", "index": 1},
            )
        )
        frames.append(
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                    "usage": {"output_tokens": 30},
                },
            )
        )
        frames.append(("message_stop", {"type": "message_stop"}))
        return frames

    text = LEAKY if mode == "secret" else ORDINARY
    if mode == "echo":
        text = ECHO_TEMPLATE.format(key=echo_key)
    frames.append(
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
    )
    # Split into word-sized fragments, the way a real tokenizer would.
    words = text.split(" ")
    for position, word in enumerate(words):
        fragment = word if position == len(words) - 1 else word + " "
        frames.append(
            (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": fragment},
                },
            )
        )
    frames.append(("content_block_stop", {"type": "content_block_stop", "index": 0}))
    frames.append(
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": len(words)},
            },
        )
    )
    frames.append(("message_stop", {"type": "message_stop"}))
    return frames


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "clean"
    # The credential the last request carried, so a test can check that the
    # gateway forwarded the one it was given rather than none at all.
    last_api_key: str | None = None
    # The body the last request carried, so a test can check what the
    # gateway asked the model for.
    last_body: dict = {}
    # The credential the "echo" mode repeats back inside the answer.
    echo_key: str = ""

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        sys.stderr.write("[fake-anthropic] " + (fmt % args) + "\n")

    def do_POST(self):  # noqa: N802 - stdlib signature
        Handler.last_api_key = self.headers.get("x-api-key")
        if not self.path.rstrip("/").endswith("/v1/messages"):
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        Handler.last_body = body if isinstance(body, dict) else {}
        model = body.get("model") if isinstance(body, dict) else None
        model = model if isinstance(model, str) and model else "stub-model"

        if body.get("stream") is False:
            payload = {
                "id": f"msg_{uuid.uuid4().hex[:24]}",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": ORDINARY}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 42, "output_tokens": 64},
            }
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.end_headers()
        for name, data in _frames(self.mode, model, Handler.echo_key):
            frame = f"event: {name}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
            self.wfile.write(frame)
            self.wfile.flush()
            time.sleep(0.005)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--mode",
        choices=sorted({"clean", "secret", "tool", "echo"}),
        default=os.environ.get("FAKE_ANTHROPIC_MODE", "clean"),
    )
    args = parser.parse_args()
    Handler.mode = args.mode
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"[fake-anthropic] listening on http://{args.host}:{args.port} "
        f"(mode={args.mode})",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
