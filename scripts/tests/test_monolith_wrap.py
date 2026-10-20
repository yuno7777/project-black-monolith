import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from monolith_wrap import (
    _Injector,
    build_mcp_config,
    discover_mcp_servers,
    load_dotenv,
)


class _Recorder(BaseHTTPRequestHandler):
    """A fake upstream that records what it was sent and answers with SSE."""

    received = []
    body = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"

    def do_POST(self):  # noqa: N802 - stdlib signature
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).received.append(
            {
                "path": self.path,
                "body": body,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        )
        payload = type(self).body
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - stdlib signature
        type(self).received.append(
            {"path": self.path, "body": b"", "headers": {k.lower(): v for k, v in self.headers.items()}}
        )
        payload = b'{"models":[]}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


class _Service:
    """One fake upstream, with its own recording of what it was sent."""

    def __init__(self):
        self.received = []
        self.body = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
        recorder = type(
            "BoundRecorder",
            (_Recorder,),
            {"received": self.received, "body": self.body},
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), recorder)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class DotenvTests(unittest.TestCase):
    def test_values_are_parsed_without_executing_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "# a comment\n"
                "\n"
                "PLAIN=value\n"
                'QUOTED="a value"\n'
                "SINGLE='another'\n"
                "export EXPORTED=yes\n"
                "SPACED = trimmed \n"
                "EMPTY=\n"
                "no_equals_sign\n",
                encoding="utf-8",
            )
            values = load_dotenv(path)
        self.assertEqual(values["PLAIN"], "value")
        self.assertEqual(values["QUOTED"], "a value")
        self.assertEqual(values["SINGLE"], "another")
        self.assertEqual(values["EXPORTED"], "yes")
        self.assertEqual(values["SPACED"], "trimmed")
        self.assertEqual(values["EMPTY"], "")
        self.assertNotIn("no_equals_sign", values)

    def test_a_missing_file_is_not_an_error(self):
        self.assertEqual(load_dotenv(Path("does/not/exist/.env")), {})


class McpConfigTests(unittest.TestCase):
    def test_stdio_servers_are_started_through_the_shield(self):
        config = build_mcp_config(
            {
                "files": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]},
                "remote": {"type": "sse", "url": "https://example.test/mcp"},
            },
            shield=Path("/opt/mcp-shield"),
            env={"MONOLITH_SESSION_ID": "sess-1", "MONOLITH_EVENT_TOKEN": "tok"},
            vector_anchor_url="http://127.0.0.1:8001",
            python="/usr/bin/python3",
        )
        servers = config["mcpServers"]
        shield = str(Path("/opt/mcp-shield"))

        # A stdio server is wrapped: the shield becomes the command and the
        # original command becomes its argument.
        self.assertEqual(servers["files"]["command"], shield)
        self.assertEqual(
            servers["files"]["args"],
            ["npx", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        self.assertEqual(servers["files"]["env"]["MONOLITH_SESSION_ID"], "sess-1")
        self.assertEqual(servers["files"]["env"]["MONOLITH_EVENT_TOKEN"], "tok")

        # A remote server is not something a stdio proxy can wrap, so it is
        # left exactly as it was rather than silently dropped.
        self.assertEqual(servers["remote"], {"type": "sse", "url": "https://example.test/mcp"})

        # The memory layer is added, and it is shielded too.
        self.assertEqual(servers["vector-anchor"]["command"], shield)
        self.assertEqual(servers["vector-anchor"]["args"][0], "/usr/bin/python3")
        self.assertTrue(
            servers["vector-anchor"]["args"][1].replace("\\", "/").endswith(
                "vector-anchor/src/mcp_server.py"
            )
        )
        self.assertEqual(
            servers["vector-anchor"]["env"]["MONOLITH_VECTOR_ANCHOR_URL"],
            "http://127.0.0.1:8001",
        )

    def test_without_a_shield_the_servers_are_still_started(self):
        config = build_mcp_config(
            {"files": {"command": "npx", "args": ["server"]}},
            shield=None,
            env={"MONOLITH_SESSION_ID": "sess-1"},
            vector_anchor_url="http://127.0.0.1:8001",
            python="/usr/bin/python3",
        )
        servers = config["mcpServers"]
        self.assertEqual(servers["files"]["command"], "npx")
        self.assertEqual(servers["vector-anchor"]["command"], "/usr/bin/python3")

    def test_the_discovered_servers_come_from_the_project_and_the_user(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"local": {"command": "node", "args": ["local.js"]}}}),
                encoding="utf-8",
            )
            with patch.object(Path, "home", return_value=project):
                (project / ".claude.json").write_text(
                    json.dumps(
                        {
                            "mcpServers": {"global": {"command": "node", "args": ["global.js"]}},
                            "projects": {
                                str(project): {
                                    "mcpServers": {"scoped": {"command": "node", "args": ["scoped.js"]}}
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                servers = discover_mcp_servers(project)
        self.assertEqual(sorted(servers), ["global", "local", "scoped"])


class InjectorTests(unittest.TestCase):
    def setUp(self):
        self.trace_audit = _Service()
        self.upstream = _Service()
        self.injector = _Injector(
            self.trace_audit.url,
            self.upstream.url,
            {
                "X-Monolith-Session-Id": "sess-wrap",
                "X-Monolith-Agent-Id": "agent-wrap",
                "X-Monolith-Tenant-Id": "tenant-wrap",
            },
        )
        self.injector.__enter__()

    def tearDown(self):
        self.injector.__exit__(None, None, None)
        self.trace_audit.close()
        self.upstream.close()

    def test_messages_go_to_the_auditor_with_the_session_stamped_on(self):
        body = json.dumps({"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]})
        request = urllib.request.Request(
            self.injector.base_url + "/v1/messages",
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": "client-secret-key",
                "authorization": "Bearer client-token",
            },
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = response.read()
            self.assertEqual(response.status, 200)
            self.assertTrue(response.headers.get("transfer-encoding"))

        # The answer is relayed as it arrived, byte for byte.
        self.assertEqual(payload, self.trace_audit.body)

        self.assertEqual(len(self.trace_audit.received), 1)
        sent = self.trace_audit.received[0]
        self.assertEqual(sent["path"], "/v1/messages")
        # The body reaches the auditor untouched.
        self.assertEqual(sent["body"].decode("utf-8"), body)
        # The session, agent and tenant are on the request.
        self.assertEqual(sent["headers"]["x-monolith-session-id"], "sess-wrap")
        self.assertEqual(sent["headers"]["x-monolith-agent-id"], "agent-wrap")
        self.assertEqual(sent["headers"]["x-monolith-tenant-id"], "tenant-wrap")
        # The client's own credential is forwarded, never replaced.
        self.assertEqual(sent["headers"]["x-api-key"], "client-secret-key")
        self.assertEqual(sent["headers"]["authorization"], "Bearer client-token")

    def test_everything_else_goes_straight_to_the_upstream(self):
        request = urllib.request.Request(self.injector.base_url + "/v1/models", method="GET")
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
        # The auditor saw nothing; the upstream saw the request.
        self.assertEqual(self.trace_audit.received, [])
        self.assertEqual(len(self.upstream.received), 1)
        self.assertEqual(self.upstream.received[0]["path"], "/v1/models")

    def test_an_unreachable_auditor_is_a_gateway_error_not_a_hang(self):
        self.trace_audit.close()
        request = urllib.request.Request(
            self.injector.base_url + "/v1/messages",
            data=b"{}",
            method="POST",
            headers={"content-type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=15)
        self.assertEqual(caught.exception.code, 502)
        self.assertIn("monolith_upstream_unreachable", caught.exception.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
