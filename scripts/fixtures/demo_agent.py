#!/usr/bin/env python3
"""A stand-in for the agent, so the gateway demo needs no API key.

This is what ``monolith wrap`` runs when it is asked to wrap something other
than a real agent. It speaks the same protocols the real agent does, which is
the point: the gateway does not know or care which agent is on the other end.

It does three things, in order:

1. Reads the MCP configuration it was handed and starts every server in it,
   exactly as an MCP client would, then asks each one what tools it has.
2. Calls the memory layer's ``retrieve`` tool and prints the answer.
3. Sends a message to ``$ANTHROPIC_BASE_URL`` and prints the answer.

Everything it prints is what an agent would actually have seen, so the demo
asserts on the same thing a user would look at.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request


def log(message: str) -> None:
    print(f"[agent] {message}", flush=True)


def read_mcp_config(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def mcp_exchange(command: str, args: list[str], env: dict) -> list[dict]:
    """Start one MCP server and drive it through the handshake.

    Returns the messages the server sent back, so the caller can look at
    what it advertised.
    """
    child = subprocess.Popen(
        [command, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **env},
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    replies: list[dict] = []
    try:
        for request_id, method, params in (
            (1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {}}),
            (2, "tools/list", {}),
        ):
            assert child.stdin is not None
            child.stdin.write(
                json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n"
            )
            child.stdin.flush()
            assert child.stdout is not None
            line = child.stdout.readline()
            if not line:
                break
            replies.append(json.loads(line))
    finally:
        try:
            if child.stdin is not None:
                child.stdin.close()
        except OSError:
            pass
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
    return replies


def call_tool(command: str, args: list[str], env: dict, name: str, arguments: dict) -> str:
    """Call one tool on an MCP server and return the text it answered with."""
    child = subprocess.Popen(
        [command, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **env},
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    try:
        assert child.stdin is not None
        for request_id, method, params in (
            (1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {}}),
            (2, "tools/call", {"name": name, "arguments": arguments}),
        ):
            child.stdin.write(
                json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n"
            )
            child.stdin.flush()
        assert child.stdout is not None
        # Two replies: the handshake and the call.
        child.stdout.readline()
        line = child.stdout.readline()
        if not line:
            return ""
        reply = json.loads(line)
        content = reply.get("result", {}).get("content") or []
        return "\n".join(part.get("text", "") for part in content if isinstance(part, dict))
    finally:
        try:
            if child.stdin is not None:
                child.stdin.close()
        except OSError:
            pass
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()


def ask_the_model(prompt: str) -> str:
    """Send a message the way an Anthropic client would, and read the answer."""
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "").rstrip("/")
    body = json.dumps(
        {
            "model": "claude-sonnet-5",
            "max_tokens": 512,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        base_url + "/v1/messages",
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": os.environ.get("ANTHROPIC_API_KEY", "demo-agent-key"),
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        raw = response.read().decode("utf-8")

    answer: list[str] = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "content_block_delta":
            delta = event.get("delta") or {}
            if delta.get("type") == "text_delta":
                answer.append(delta.get("text", ""))
    return "".join(answer)


def main() -> int:
    config_path = None
    arguments = sys.argv[1:]
    for index, value in enumerate(arguments):
        if value == "--mcp-config" and index + 1 < len(arguments):
            config_path = arguments[index + 1]

    log(f"base url  {os.environ.get('ANTHROPIC_BASE_URL', '(unset)')}")
    # The agent is not told its session id. The gateway stamps it on every
    # request instead, so a client cannot forge its way into another
    # session's ledger - and cannot opt out of its own.
    log("session   (not disclosed to the agent)")

    if config_path and os.path.isfile(config_path):
        config = read_mcp_config(config_path)
        servers = config.get("mcpServers") or {}
        log(f"mcp servers: {', '.join(sorted(servers)) or '(none)'}")
        for name in sorted(servers):
            spec = servers[name] or {}
            command = spec.get("command")
            if not command:
                continue
            env = spec.get("env") or {}
            replies = mcp_exchange(command, [str(a) for a in spec.get("args") or []], env)
            tools: list[str] = []
            for reply in replies:
                for tool in (reply.get("result") or {}).get("tools") or []:
                    tools.append(tool.get("name", "?"))
            log(f"  {name}: {len(tools)} tool(s) {tools}")

            if "retrieve" in tools:
                answer = call_tool(
                    command,
                    [str(a) for a in spec.get("args") or []],
                    env,
                    "retrieve",
                    {"query": "how does the corpus poisoning detector work?", "k": 3},
                )
                log("  retrieve ->")
                for line in answer.splitlines():
                    log(f"    {line}")

    log("asking the model for a configuration with an access key...")
    answer = ask_the_model("What is the access key id for the production bucket?")
    log("the model answered:")
    for line in answer.splitlines():
        log(f"  {line}")
    print("AGENT_ANSWER_BEGIN")
    print(answer)
    print("AGENT_ANSWER_END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
