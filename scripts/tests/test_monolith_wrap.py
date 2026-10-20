import http.client
import io
import json
import os
import re
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from monolith_wrap import (
    _Injector,
    _InjectorHandler,
    build_child_env,
    build_mcp_config,
    build_shield_env,
    credential_transport_is_trusted,
    discover_mcp_servers,
    load_dotenv,
    mint_session_id,
    print_session_report,
    redact_config_secrets,
    resolve_setting,
    wait_for_spool_drain,
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
                # The raw list, in the order it arrived: a dict of the same
                # headers would hide a duplicate that a server reading the
                # first occurrence would pick up.
                "header_list": list(self.headers.items()),
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
            {
                "path": self.path,
                "body": b"",
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "header_list": list(self.headers.items()),
            }
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


class SettingTests(unittest.TestCase):
    def test_the_process_environment_wins_over_the_dotenv_file(self):
        # The launcher's own rule: the process's environment always wins
        # over the file, so an operator can override a setting for one run
        # without editing the file the stack reads.
        with patch.dict(os.environ):
            os.environ.pop("MONOLITH_TEST_SETTING", None)
            self.assertEqual(
                resolve_setting("MONOLITH_TEST_SETTING", {"MONOLITH_TEST_SETTING": "from-file"}),
                "from-file",
            )
            os.environ["MONOLITH_TEST_SETTING"] = "from-environment"
            self.assertEqual(
                resolve_setting("MONOLITH_TEST_SETTING", {"MONOLITH_TEST_SETTING": "from-file"}),
                "from-environment",
            )
            # With neither, the caller's default stands.
            os.environ.pop("MONOLITH_TEST_SETTING")
            self.assertIsNone(resolve_setting("MONOLITH_TEST_SETTING", {}))
            self.assertEqual(resolve_setting("MONOLITH_TEST_SETTING", {}, "fallback"), "fallback")


class TransportTests(unittest.TestCase):
    def test_a_credential_may_only_cross_the_network_over_https(self):
        # The modules apply this rule to their own delivery; the launcher
        # holds the operator token and answers the same way.
        self.assertTrue(credential_transport_is_trusted("https://dashboard.example.com", False))
        self.assertTrue(credential_transport_is_trusted("http://127.0.0.1:3000", False))
        self.assertTrue(credential_transport_is_trusted("http://localhost:3000", False))
        self.assertTrue(credential_transport_is_trusted("http://[::1]:3000", False))
        self.assertFalse(credential_transport_is_trusted("http://dashboard.example.com", False))
        self.assertFalse(credential_transport_is_trusted("http://10.0.0.5:3000", False))
        # Only the operator can say the network is trusted.
        self.assertTrue(credential_transport_is_trusted("http://dashboard.example.com", True))
        # A scheme that is not HTTP at all is not a transport we speak.
        self.assertFalse(credential_transport_is_trusted("ftp://dashboard.example.com", False))

    def test_the_session_report_is_skipped_when_the_token_would_travel_in_the_clear(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            print_session_report(
                "http://dashboard.example.com",
                "sess-1",
                "operator-token-value",
                allow_insecure=False,
            )
        output = buffer.getvalue()
        self.assertIn("skipped", output)
        # And the token itself is not echoed into the console.
        self.assertNotIn("operator-token-value", output)

    def test_the_operator_token_does_not_go_through_an_ambient_proxy(self):
        """urllib honours http_proxy by default.

        A loopback dashboard passes the transport check, but with an
        http_proxy exported the request would be handed to that proxy —
        and the operator token would go with it, in cleartext, to a host
        that is not the loopback address the check approved.
        """
        seen: list[str] = []

        class _Proxy(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib signature
                seen.append(self.headers.get("authorization") or "")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.lower() not in ("http_proxy", "https_proxy")
            }
            environment["http_proxy"] = f"http://127.0.0.1:{server.server_address[1]}"
            with patch.dict(os.environ, environment, clear=True):
                print_session_report(
                    "http://127.0.0.1:9/unreachable",
                    "sess-1",
                    "operator-token-value",
                    allow_insecure=False,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        # The proxy saw nothing: the request never went to it.
        self.assertEqual(seen, [])


class SessionReportTests(unittest.TestCase):
    def test_a_truncated_report_says_the_counts_cover_only_the_page(self):
        """A session larger than one page must not read as a whole run.

        The dashboard reports the session's true size and the counts it
        could compute; the operator has to be told which is which, or the
        breakdown reads as if it covered every event.
        """
        payload = json.dumps(
            {
                "session_id": "sess-1",
                "summary": {
                    "total": 5000,
                    "counted": 1000,
                    "truncated": True,
                    "detections": 12,
                    "blocks": 3,
                    "quarantines": 0,
                    "revocations": 0,
                    "by_severity": {"critical": 10, "warning": 2, "info": 988},
                    "by_module": {"mcp-shield": 1000},
                    "by_event_type": {"schema_mismatch": 1000},
                },
                "events": [],
            }
        ).encode("utf-8")

        class _Dashboard(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib signature
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Dashboard)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                print_session_report(
                    f"http://127.0.0.1:{server.server_address[1]}",
                    "sess-1",
                    "operator-token-value",
                    allow_insecure=False,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        output = buffer.getvalue()
        # The session's true size is what the operator asked for.
        self.assertIn("5000", output)
        # And the breakdown says what it covers.
        self.assertIn("the counts below cover the first 1000", output)


class PlanRedactionTests(unittest.TestCase):
    def test_the_plan_does_not_print_a_secret(self):
        config = build_mcp_config(
            {
                "files": {
                    "command": "npx",
                    "args": ["server"],
                    "env": {"ANTHROPIC_API_KEY": "sk-live-0000"},
                }
            },
            shield=Path("/opt/mcp-shield"),
            env={
                "MONOLITH_SESSION_ID": "sess-1",
                "MONOLITH_EVENT_TOKEN": "ingest-token-1111",
                "MCP_SHIELD_KEY": "hmac-key-2222",
            },
            vector_anchor_url="http://127.0.0.1:8001",
            python="/usr/bin/python3",
        )
        printed = json.dumps(redact_config_secrets(config))
        # The dashboard's ingest token, the fingerprinting key and the
        # user's own MCP server secrets are all in that configuration.
        self.assertNotIn("sk-live-0000", printed)
        self.assertNotIn("ingest-token-1111", printed)
        self.assertNotIn("hmac-key-2222", printed)
        # The session id is not a secret, and the plan is useless without it.
        self.assertIn("sess-1", printed)
        # The file on disk keeps the real values: the shield needs them.
        self.assertEqual(
            config["mcpServers"]["files"]["env"]["ANTHROPIC_API_KEY"],
            "sk-live-0000",
        )
        self.assertEqual(
            config["mcpServers"]["files"]["env"]["MONOLITH_EVENT_TOKEN"],
            "ingest-token-1111",
        )

    def test_the_plan_does_not_print_a_secret_passed_as_an_argument(self):
        """A secret on the command line is still a secret.

        The plan is printed for a human to read, and a human pastes it into
        an issue. A server started as ``--token ghp_...`` leaks exactly as
        much as one started with the token in its environment.
        """
        config = build_mcp_config(
            {
                "files": {
                    "command": "npx",
                    "args": ["-y", "server", "--token", "ghp_live_0000"],
                    "env": {},
                },
                "inline": {
                    "command": "server",
                    "args": ["--api-key=sk-live-0000"],
                    "env": {},
                },
            },
            shield=Path("/opt/mcp-shield"),
            env={"MONOLITH_SESSION_ID": "sess-1"},
            vector_anchor_url="http://127.0.0.1:8001",
            python="/usr/bin/python3",
        )
        printed = json.dumps(redact_config_secrets(config))
        self.assertNotIn("ghp_live_0000", printed)
        self.assertNotIn("sk-live-0000", printed)
        # The flag itself is not a secret, and the plan is useless without it.
        self.assertIn("--token", printed)
        # And the file on disk keeps the real value: the server needs it.
        self.assertEqual(
            config["mcpServers"]["files"]["args"][-1],
            "ghp_live_0000",
        )

    def test_the_short_secret_flags_are_redacted_and_the_path_is_not(self):
        """A short flag is a secret flag too, and a path is not.

        ``--pat`` carries a personal access token, ``--bearer`` a bearer
        credential and ``--pw`` a password. None of them contains one of the
        long markers, so a substring match missed all three — and adding
        "pat" to that list would have redacted every ``--path`` the operator
        configured, which is a different thing entirely.
        """
        config = build_mcp_config(
            {
                "files": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "server",
                        "--pat",
                        "ghp_live_0000",
                        "--bearer",
                        "bearer-value-3333",
                        "--pw",
                        "hunter2",
                        "--path",
                        "/tmp/data",
                    ],
                    "env": {},
                },
                "inline": {
                    "command": "server",
                    "args": ["--pat=ghp_inline_0000"],
                    "env": {},
                },
            },
            shield=Path("/opt/mcp-shield"),
            env={"MONOLITH_SESSION_ID": "sess-1"},
            vector_anchor_url="http://127.0.0.1:8001",
            python="/usr/bin/python3",
        )
        printed = json.dumps(redact_config_secrets(config))
        self.assertNotIn("ghp_live_0000", printed)
        self.assertNotIn("bearer-value-3333", printed)
        self.assertNotIn("hunter2", printed)
        self.assertNotIn("ghp_inline_0000", printed)
        # The flag itself is not a secret, and the plan is useless without it.
        self.assertIn("--pat", printed)
        self.assertIn("--bearer", printed)
        self.assertIn("--pw", printed)
        # A path is not a secret. Redacting it would hide the only part of
        # the configuration an operator needs to check.
        self.assertIn("/tmp/data", printed)
        # And the file on disk keeps the real values: the server needs them.
        # The wrapped server's own command is the first argument, so the
        # flags start at the second.
        self.assertEqual(
            config["mcpServers"]["files"]["args"][4],
            "ghp_live_0000",
        )
        self.assertEqual(
            config["mcpServers"]["files"]["args"][6],
            "bearer-value-3333",
        )
        self.assertEqual(
            config["mcpServers"]["files"]["args"][8],
            "hunter2",
        )


class ChildEnvTests(unittest.TestCase):
    def test_the_operator_credentials_do_not_reach_the_agent(self):
        """The agent is the thing this system defends against.

        It starts processes of its own — the MCP servers it runs, the tools
        it calls, the scripts it writes — and every one of them inherits the
        agent's environment. An exported operator credential would
        therefore reach all of them, and the operator's ledger credential
        would let the agent write the incident record that describes it.
        """
        base = {
            "PATH": "/usr/bin",
            "HOME": "/home/operator",
            "ANTHROPIC_API_KEY": "the-anthropic-key-the-operator-configured",
            "MONOLITH_OPERATOR_TOKEN": "operator-token-0001",
            "MONOLITH_EVENT_TOKEN": "ingest-token-0002",
            "MONOLITH_EVENT_TOKEN_MCP_SHIELD": "module-token-0003",
            "MONOLITH_ADMIN_TOKEN": "admin-token-0004",
            "MCP_SHIELD_KEY": "hmac-key-0005",
            "PBM_SECRET_PROVIDER_TOKEN": "provider-token-0006",
            "A_TOKEN_FOR_SOMETHING_ELSE": "not-ours-to-take",
        }
        child = build_child_env(base)

        for name in (
            "MONOLITH_OPERATOR_TOKEN",
            "MONOLITH_EVENT_TOKEN",
            "MONOLITH_EVENT_TOKEN_MCP_SHIELD",
            "MONOLITH_ADMIN_TOKEN",
            "MCP_SHIELD_KEY",
            "PBM_SECRET_PROVIDER_TOKEN",
        ):
            self.assertNotIn(name, child, f"{name} must not reach the agent")

        # The agent's own credential is the agent's to spend, and the point
        # of the gateway is that the agent can still reach the provider.
        self.assertEqual(
            child["ANTHROPIC_API_KEY"],
            "the-anthropic-key-the-operator-configured",
        )
        # And the environment it needs to run at all.
        self.assertEqual(child["PATH"], "/usr/bin")
        self.assertEqual(child["HOME"], "/home/operator")
        # A credential that belongs to something else is not ours to take.
        self.assertEqual(child["A_TOKEN_FOR_SOMETHING_ELSE"], "not-ours-to-take")

    def test_a_lower_case_credential_is_hidden_too(self):
        """Environment variable names are case-insensitive on Windows."""
        child = build_child_env({"monolith_operator_token": "operator-token-0007"})
        self.assertNotIn("monolith_operator_token", child)


class SessionIdTests(unittest.TestCase):
    def test_the_session_id_cannot_be_guessed_by_anything_else_on_the_host(self):
        """The session id is the key every layer correlates on.

        It is therefore also the key something would need in order to file
        events into this run's ledger. A clock and a pid are guessable by
        anything else running on the machine, so the id has to carry real
        randomness.
        """
        first = mint_session_id()
        second = mint_session_id()

        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("monolith-"))
        # A v4 uuid: 122 bits of randomness behind the readable prefix.
        self.assertEqual(uuid.UUID(first.removeprefix("monolith-")).version, 4)
        # And not the old clock-and-pid shape, which anybody could compute.
        self.assertIsNone(re.match(r"^monolith-\d+-[0-9a-f]+$", first))


class SpoolTests(unittest.TestCase):
    def test_the_spool_is_waited_for_before_the_work_directory_goes_away(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "outbox.jsonl"
            # Something still in the spool means it has not been delivered.
            spool.write_text('{"event_id":"e1"}\n', encoding="utf-8")
            self.assertFalse(wait_for_spool_drain(spool, budget=0.3))
            # An empty spool has drained.
            spool.write_text("", encoding="utf-8")
            self.assertTrue(wait_for_spool_drain(spool, budget=0.3))
            # A spool that was never created has nothing to wait for.
            spool.unlink()
            self.assertTrue(wait_for_spool_drain(spool, budget=0.3))


class ShieldEnvTests(unittest.TestCase):
    def test_the_tool_layer_is_told_the_network_is_trusted(self):
        """The operator's answer lives in one .env file, and both layers read it.

        The launcher honours MONOLITH_ALLOW_INSECURE_DASHBOARD for its own
        report; MCP-Shield applies the same rule to its own delivery. If
        the shield is not told, the tool layer silently stops delivering
        while the launcher's report still works.
        """
        with tempfile.TemporaryDirectory() as directory:
            env = build_shield_env(
                dashboard_url="http://dashboard.internal:3000",
                workdir=Path(directory),
                tenant_id="default",
                agent_id="claude-code",
                session_id="sess-1",
                event_token="ingest-token-1111",
                shield_key="hmac-key-2222",
                allow_insecure_dashboard=True,
            )
        self.assertEqual(env["MONOLITH_ALLOW_INSECURE_DASHBOARD"], "true")

    def test_the_flag_is_absent_unless_the_operator_set_it(self):
        with tempfile.TemporaryDirectory() as directory:
            env = build_shield_env(
                dashboard_url="https://dashboard.example.com",
                workdir=Path(directory),
                tenant_id="default",
                agent_id="claude-code",
                session_id="sess-1",
            )
        self.assertNotIn("MONOLITH_ALLOW_INSECURE_DASHBOARD", env)


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

    def test_the_clients_credential_does_not_go_through_an_ambient_proxy(self):
        """The hop to the auditor carries the client's own credential.

        urllib honours http_proxy by default, and on Windows it reads the
        registry's ProxyEnable and ProxyServer as well, so a request meant
        for the local auditor would be handed to whatever proxy the host
        happens to be configured with — and the client's credential would
        go with it, in cleartext, to a host that is not the auditor.
        """
        seen: list[str] = []

        class _Proxy(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - stdlib signature
                seen.append(self.headers.get("x-api-key") or "")
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        proxy = ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
        thread = Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.lower() not in ("http_proxy", "https_proxy")
            }
            environment["http_proxy"] = f"http://127.0.0.1:{proxy.server_address[1]}"
            with patch.dict(os.environ, environment, clear=True):
                body = json.dumps(
                    {"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]}
                )
                # The client side talks to the injector over a plain
                # socket: urllib would apply the same ambient proxy to it,
                # and the request under test would never reach the injector
                # at all.
                parsed = urllib.parse.urlsplit(self.injector.base_url)
                connection = http.client.HTTPConnection(
                    parsed.hostname, parsed.port, timeout=15
                )
                try:
                    connection.request(
                        "POST",
                        "/v1/messages",
                        body=body.encode("utf-8"),
                        headers={
                            "content-type": "application/json",
                            "x-api-key": "client-secret-key",
                        },
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                finally:
                    connection.close()
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=5)

        # The proxy saw nothing: the hop never went to it.
        self.assertEqual(seen, [])
        # And the auditor got the request, with the client's credential.
        self.assertEqual(len(self.trace_audit.received), 1)
        self.assertEqual(
            self.trace_audit.received[0]["headers"]["x-api-key"], "client-secret-key"
        )

    def test_a_client_cannot_forge_the_session_it_is_stamped_with(self):
        # The launcher promises that the session id on every request is the
        # one it minted, whatever the client sent. A client that could choose
        # its own would file its findings in another session's ledger, and one
        # that could blank the header would opt out of its own session. Both
        # are attempted here, in every casing the header can arrive in, and
        # with a duplicate that a server reading the first occurrence would
        # pick up.
        #
        # The two spellings are tried in both orders, because which one
        # survived used to depend on the order they arrived in rather than on
        # anything the launcher decided.
        body = json.dumps({"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]})
        spellings = [
            [
                "X-Monolith-Session-Id: forged-session-again",
                "x-monolith-session-id: forged-session",
            ],
            [
                "x-monolith-session-id: forged-session",
                "X-Monolith-Session-Id: forged-session-again",
            ],
        ]

        for order in spellings:
            with self.subTest(order=order[0]):
                self.trace_audit.received.clear()
                raw = (
                    "POST /v1/messages HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{self.injector.port}\r\n"
                    "Content-Type: application/json\r\n"
                    + "\r\n".join(order)
                    + "\r\n"
                    "X-MONOLITH-TENANT-ID: forged-tenant\r\n"
                    "x-monolith-agent-id: \r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "\r\n"
                    f"{body}"
                )
                with socket.create_connection(("127.0.0.1", self.injector.port), timeout=15) as connection:
                    connection.sendall(raw.encode("utf-8"))
                    connection.settimeout(10)
                    # The injector answers with a chunked stream and keeps the
                    # connection open, so read until the terminating chunk
                    # rather than until the socket closes. The auditor records
                    # the request before it answers, so the response is proof
                    # it was recorded.
                    received = b""
                    while b"0\r\n\r\n" not in received:
                        try:
                            chunk = connection.recv(65536)
                        except TimeoutError:
                            break
                        if not chunk:
                            break
                        received += chunk

                self.assertEqual(len(self.trace_audit.received), 1)
                sent = self.trace_audit.received[0]
                names = [name.lower() for name, _ in sent["header_list"]]
                # One of each, not two: a duplicate is what a server reading
                # the first occurrence would act on.
                self.assertEqual(names.count("x-monolith-session-id"), 1)
                self.assertEqual(names.count("x-monolith-tenant-id"), 1)
                self.assertEqual(names.count("x-monolith-agent-id"), 1)
                # And the one that is there is the launcher's, not the client's.
                self.assertEqual(sent["headers"]["x-monolith-session-id"], "sess-wrap")
                self.assertEqual(sent["headers"]["x-monolith-tenant-id"], "tenant-wrap")
                self.assertEqual(sent["headers"]["x-monolith-agent-id"], "agent-wrap")
                # Nothing the client sent survives under any casing.
                for _, value in sent["header_list"]:
                    self.assertNotIn("forged", value)

    def test_the_session_id_does_not_travel_to_the_model_provider(self):
        # The session id is how a run is attributed, and it is the key a
        # caller would need to file events into that run's ledger. The model
        # provider has no business knowing it: only the auditor does.
        request = urllib.request.Request(self.injector.base_url + "/v1/models", method="GET")
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()

        self.assertEqual(len(self.upstream.received), 1)
        names = [name.lower() for name, _ in self.upstream.received[0]["header_list"]]
        self.assertNotIn("x-monolith-session-id", names)
        self.assertNotIn("x-monolith-agent-id", names)
        self.assertNotIn("x-monolith-tenant-id", names)

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

    def test_a_target_that_only_reaches_the_auditor_by_another_spelling_still_reaches_it(self):
        """The reasoning layer must not be skippable by spelling the path
        differently.

        A fragment is not part of the request, a front end collapses dot
        segments, and a doubled slash is one path. A target that only
        *reaches* /v1/messages by another spelling used to go to the model
        provider instead — which means no PII redaction, no divergence
        check, no stamping and no ledger event.
        """
        body = json.dumps({"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]})
        for target in ("/v1/messages#f", "/v1/./messages", "/v1//messages", "/v1/messages/"):
            with self.subTest(target=target):
                self.trace_audit.received.clear()
                self.upstream.received.clear()
                raw = (
                    f"POST {target} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{self.injector.port}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "\r\n"
                    f"{body}"
                )
                with socket.create_connection(("127.0.0.1", self.injector.port), timeout=15) as connection:
                    connection.sendall(raw.encode("utf-8"))
                    connection.settimeout(10)
                    received = b""
                    while b"0\r\n\r\n" not in received:
                        try:
                            chunk = connection.recv(65536)
                        except TimeoutError:
                            break
                        if not chunk:
                            break
                        received += chunk

                # The auditor saw it, and the model provider did not.
                self.assertEqual(len(self.trace_audit.received), 1)
                self.assertEqual(self.upstream.received, [])

    def test_a_redirect_from_the_upstream_does_not_carry_the_client_credential(self):
        """A redirect must never decide where the client's credential goes.

        urllib's default handler re-issues the request to whatever the
        Location header names, and copies every header except
        content-length and content-type onto it — x-api-key among them.
        """
        taken: list[dict] = []

        class _Thief(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - stdlib signature
                taken.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_args):
                pass

        thief = ThreadingHTTPServer(("127.0.0.1", 0), _Thief)
        thief_thread = Thread(target=thief.serve_forever, daemon=True)
        thief_thread.start()

        class _Redirector(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - stdlib signature
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self.send_response(302)
                self.send_header(
                    "location", f"http://127.0.0.1:{thief.server_address[1]}/collect"
                )
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        redirector = ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
        redirector_thread = Thread(target=redirector.serve_forever, daemon=True)
        redirector_thread.start()

        try:
            injector = _Injector(
                self.trace_audit.url,
                f"http://127.0.0.1:{redirector.server_address[1]}",
                {"X-Monolith-Session-Id": "sess-wrap"},
            )
            injector.__enter__()
            try:
                request = urllib.request.Request(
                    injector.base_url + "/v1/models",
                    data=b"{}",
                    method="POST",
                    headers={"x-api-key": "client-secret-key"},
                )
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=15)
                self.assertEqual(caught.exception.code, 302)
            finally:
                injector.__exit__(None, None, None)
        finally:
            redirector.shutdown()
            redirector.server_close()
            redirector_thread.join(timeout=5)
            thief.shutdown()
            thief.server_close()
            thief_thread.join(timeout=5)

        # The redirect was not followed, so the credential never left.
        self.assertEqual(taken, [])


class InjectorLimitsTests(unittest.TestCase):
    """What a client can ask the injector to hold in memory, and for how
    long."""

    def setUp(self):
        self.trace_audit = _Service()
        self.upstream = _Service()
        self.injector = _Injector(
            self.trace_audit.url,
            self.upstream.url,
            {"X-Monolith-Session-Id": "sess-wrap"},
        )
        self.injector.__enter__()

    def tearDown(self):
        self.injector.__exit__(None, None, None)
        self.trace_audit.close()
        self.upstream.close()

    def test_an_oversized_body_is_refused_before_it_is_read(self):
        original = _InjectorHandler.max_forward_bytes
        _InjectorHandler.max_forward_bytes = 64
        try:
            request = urllib.request.Request(
                self.injector.base_url + "/v1/messages",
                data=b"x" * 128,
                method="POST",
                headers={"content-type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=15)
        finally:
            _InjectorHandler.max_forward_bytes = original
        self.assertEqual(caught.exception.code, 413)
        # Nothing was forwarded.
        self.assertEqual(self.trace_audit.received, [])

    def test_a_body_that_never_arrives_does_not_pin_the_handler(self):
        original = _InjectorHandler.request_read_timeout
        _InjectorHandler.request_read_timeout = 0.5
        try:
            with socket.create_connection(("127.0.0.1", self.injector.port), timeout=15) as connection:
                connection.sendall(
                    b"POST /v1/messages HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 100\r\n"
                    b"\r\n"
                )
                connection.settimeout(10)
                received = b""
                while b"\r\n\r\n" not in received:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    received += chunk
        finally:
            _InjectorHandler.request_read_timeout = original
        self.assertIn(b"408", received.split(b"\r\n")[0])

    def test_a_malformed_content_length_is_refused(self):
        with socket.create_connection(("127.0.0.1", self.injector.port), timeout=15) as connection:
            connection.sendall(
                b"POST /v1/messages HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Length: not-a-number\r\n"
                b"\r\n"
            )
            connection.settimeout(10)
            received = b""
            while b"\r\n\r\n" not in received:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                received += chunk
        self.assertIn(b"400", received.split(b"\r\n")[0])


if __name__ == "__main__":
    unittest.main()
