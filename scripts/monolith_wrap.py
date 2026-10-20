#!/usr/bin/env python3
"""monolith wrap — run an agent inside the defense stack.

One command puts a whole agent session behind all three layers at once:

    monolith wrap --claude

What it does, in order:

1. **Mints a session id.** One id for the run, handed to every layer, so
   the tool-layer, memory-layer and reasoning-layer detections for this run
   are correlated with each other. This is the key the cross-layer circuit
   breaker works on.
2. **Rewrites the agent's MCP configuration.** Every MCP server the agent
   would have started is started through MCP-Shield instead, so tool schemas
   are fingerprinted and poisoning is caught. VectorAnchor's memory layer is
   added as a server the agent can actually call.
3. **Puts the reasoning layer in the model's path.** A local proxy takes
   over ``ANTHROPIC_BASE_URL``, stamps the session id onto every request and
   forwards it to TraceAudit, which audits the answer before the agent
   reads it. The agent's own credential is forwarded untouched; the proxy
   holds no key.
4. **Reports.** When the agent exits, the ledger is read back for that
   session and a short summary is printed: what was detected, what was
   blocked, what was quarantined, whether the session was revoked.

The agent does not know any of this is happening. That is the point: a
defense the agent can detect is a defense the agent can route around.

Nothing here needs a package install. It is standard library only, so it
runs on the machine that has the agent, not only inside the container.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3000"
DEFAULT_VECTOR_ANCHOR_URL = "http://127.0.0.1:8001"
DEFAULT_TRACE_AUDIT_URL = "http://127.0.0.1:8002"
DEFAULT_UPSTREAM_URL = "https://api.anthropic.com"

# Headers that describe one hop and must not be copied onto the next.
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
}

# The namespace the launcher owns. Nothing a client sends in it survives:
# the session, agent and tenant on the wire are the ones the launcher
# minted, never the ones a client asked for.
CORRELATION_PREFIX = "x-monolith-"

# The largest request the injector will forward. The Messages API caps its
# own request bodies, so anything larger is not a request worth relaying —
# and reading it into memory first would let one client ask for as much as
# it liked.
MAX_FORWARD_BYTES = 32 * 1024 * 1024

# How long the injector waits for the body a client announced.
REQUEST_READ_TIMEOUT_SECONDS = 30.0


# --- small helpers ---------------------------------------------------------


def load_dotenv(path: Path) -> dict[str, str]:
    """Read a .env file without executing anything in it.

    The repository ships one for the Compose stack, and the launcher needs
    the same module tokens the containers use — but a .env file can contain
    values a shell would expand, so it is parsed rather than sourced.
    """
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export "):].strip()
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def resolve_setting(name: str, dotenv: dict[str, str], default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value:
        return value
    value = dotenv.get(name)
    if value:
        return value
    return default


def mint_session_id() -> str:
    """A session id that nothing else on the machine can guess.

    The session id is the key every layer correlates on, so it is also the
    key something would need in order to file events into this run's ledger.
    A clock and a pid are guessable by anything else running on the host, so
    the id carries 122 bits of randomness instead: a caller that cannot
    guess it cannot pretend to be this run.
    """
    return f"monolith-{uuid.uuid4()}"


def _is_loopback_host(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def credential_transport_is_trusted(url: str, allow_insecure: bool) -> bool:
    """Whether a credential may be sent to this address over this scheme.

    The modules apply the same rule to their own delivery — HTTPS
    everywhere, plain HTTP only to loopback, and only when the operator
    says the network is trusted — and the launcher holds the operator
    token, so it answers the same way. The default is to refuse: a
    credential sent in cleartext to a remote host is a credential on the
    wire, and no configuration mistake should turn that on by accident.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http":
        return False
    if _is_loopback_host(parsed.hostname or ""):
        return True
    return allow_insecure


# The launcher's own settings that carry no secret, so the plan can show
# them. Everything else in an environment block is redacted: the plan is
# printed for a human to read, and a human pastes it into an issue.
PLAN_VISIBLE_ENV = {
    "MONOLITH_DASHBOARD_URL",
    "MONOLITH_EVENT_OUTBOX_PATH",
    "MCP_SHIELD_BASELINE",
    "MCP_SHIELD_MODE",
    "MONOLITH_TENANT_ID",
    "MONOLITH_AGENT_ID",
    "MONOLITH_SESSION_ID",
    "MONOLITH_VECTOR_ANCHOR_URL",
}


# Argument flags whose value is a secret. A secret on the command line is
# still a secret, and the plan is printed for a human to read.
SECRET_ARG_FLAGS = ("key", "token", "secret", "password", "passwd", "credential", "auth")


def _is_secret_arg_flag(flag: str) -> bool:
    lowered = flag.lower()
    return any(marker in lowered for marker in SECRET_ARG_FLAGS)


def redact_config_secrets(config: dict) -> dict:
    """A copy of the configuration with every secret in it redacted.

    The file written to disk keeps the real values — the shield needs the
    ingest token and the fingerprinting key — but the printed plan does not.
    The plan carries the dashboard's ingest token, MCP-Shield's HMAC key
    and every secret in the user's own MCP server environments, and it is
    printed for a human to read.

    Both places a secret can sit are covered: the ``env`` block, and the
    argument list. A server started as ``--token ghp_...`` leaks exactly as
    much as one started with ``GITHUB_TOKEN=ghp_...`` in its environment.
    """
    redacted = json.loads(json.dumps(config))
    for spec in (redacted.get("mcpServers") or {}).values():
        if not isinstance(spec, dict):
            continue
        env = spec.get("env")
        if isinstance(env, dict):
            for name in list(env):
                if name in PLAN_VISIBLE_ENV:
                    continue
                value = env[name]
                if isinstance(value, str):
                    env[name] = f"<redacted: {len(value)} characters>" if value else "<empty>"
                else:
                    env[name] = "<redacted>"
        args = spec.get("args")
        if isinstance(args, list):
            redact = False
            for position, arg in enumerate(args):
                if not isinstance(arg, str):
                    continue
                if redact:
                    args[position] = "<redacted>"
                    redact = False
                    continue
                if arg.startswith("-") and "=" in arg:
                    flag, _, value = arg.partition("=")
                    if _is_secret_arg_flag(flag) and value:
                        args[position] = f"{flag}=<redacted: {len(value)} characters>"
                    continue
                if arg.startswith("-") and _is_secret_arg_flag(arg):
                    redact = True
    return redacted


def wait_for_spool_drain(spool_path: Path, budget: float = 8.0) -> bool:
    """Wait for MCP-Shield to deliver what it spooled.

    The shield delivers asynchronously and makes one final forced pass as it
    exits, which takes a moment after the agent that started it is gone.
    Removing its spool before that pass finishes would discard detections
    that were never delivered, and the session report would understate the
    run by exactly the findings that mattered.
    """
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        try:
            if not spool_path.exists() or spool_path.stat().st_size == 0:
                return True
        except OSError:
            return True
        time.sleep(0.1)
    return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow a redirect.

    urllib's default handler re-issues the request to whatever the
    ``Location`` header names and copies every header except
    content-length and content-type onto it — the client's ``x-api-key``
    among them. A redirect must never decide where a credential goes.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(use_proxy: bool = True) -> urllib.request.OpenerDirector:
    """The opener every outbound request goes through.

    It never follows a redirect, and it can be told to ignore the
    ambient proxy.
    """
    handlers: list[urllib.request.BaseHandler] = [_NoRedirect]
    if not use_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def http_get_json(
    url: str,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
    use_proxy: bool = True,
):
    """Fetch a JSON document.

    ``use_proxy=False`` ignores the ambient ``http_proxy``/``https_proxy``
    environment. urllib honours them by default, so a request that looks
    like it is going to a loopback address can be handed to a proxy on the
    way — and a credential in that request would go with it.
    """
    request = urllib.request.Request(url, headers=headers or {})
    with _opener(use_proxy).open(request, timeout=timeout) as response:
        body = response.read()
    return json.loads(body)


def service_healthy(url: str) -> bool:
    try:
        http_get_json(url, timeout=3.0)
        return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


# --- the local injector ----------------------------------------------------


class _InjectorHandler(BaseHTTPRequestHandler):
    """Forwards the agent's model traffic, stamping the session id on it.

    Only ``/v1/messages`` goes through TraceAudit: that is the traffic that
    carries a model's answer, and therefore the only traffic with anything
    to audit. Everything else (token counting, model listings) goes straight
    upstream, because a defense that breaks the parts of the protocol it
    does not care about is just an outage.
    """

    protocol_version = "HTTP/1.1"
    server_version = "monolith-injector/1.0"

    # Set by the launcher before the server starts.
    trace_audit_url: str = DEFAULT_TRACE_AUDIT_URL
    upstream_url: str = DEFAULT_UPSTREAM_URL
    correlation: dict[str, str] = {}
    read_timeout: float = 600.0
    # The bounds on what a client can ask this proxy to hold in memory.
    max_forward_bytes: int = MAX_FORWARD_BYTES
    request_read_timeout: float = REQUEST_READ_TIMEOUT_SECONDS

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        sys.stderr.write("[injector] " + (fmt % args) + "\n")

    def _forward_headers(self, *, stamped: bool) -> dict[str, str]:
        """The headers to forward, with the correlation namespace owned here.

        Every client-supplied ``X-Monolith-*`` header is dropped, in whatever
        casing it arrived. HTTP header names are case-insensitive, so a
        client that sent the same name twice under two spellings would
        otherwise get one of its own values onto the wire — and which one
        survived would depend on the order they arrived in, not on anything
        the launcher decided.
        """
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP
            and not key.lower().startswith(CORRELATION_PREFIX)
        }
        headers["accept-encoding"] = "identity"
        if stamped:
            headers.update(self.correlation)
        return headers

    def _normalized_path(self) -> str:
        """The request target resolved the way a server would resolve it.

        The raw target is not the path: a fragment is not part of the
        request, a front end collapses dot segments, and a doubled slash
        is one path. Comparing the raw target to "/v1/messages" lets a
        target that only *reaches* that endpoint by another spelling skip
        the auditor entirely — and the auditor is the whole reasoning
        layer.
        """
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        segments: list[str] = []
        for segment in path.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if segments:
                    segments.pop()
                continue
            segments.append(segment)
        return "/" + "/".join(segments)

    def _is_messages_path(self) -> bool:
        return self._normalized_path() == "/v1/messages"

    def _target(self) -> str:
        if self._is_messages_path():
            return self.trace_audit_url.rstrip("/") + "/v1/messages"
        return self.upstream_url.rstrip("/") + self.path

    def _proxy(self, method: str) -> None:
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            self._refuse(400, "the content-length header is not a number")
            return
        if length > self.max_forward_bytes:
            self._refuse(413, "the request body is too large")
            return
        try:
            # The client's body is bounded in time as well as in size: a
            # client that announces a length and then stops would otherwise
            # pin this handler thread for as long as it cared to.
            self.connection.settimeout(self.request_read_timeout)
            body = self.rfile.read(length) if length else b""
        except TimeoutError:
            self._refuse(408, "the request body did not arrive in time")
            return
        except OSError as error:
            self._refuse(400, f"the request body could not be read: {error}")
            return
        finally:
            # The answer is a long-lived stream, so the socket goes back to
            # waiting as long as it takes.
            self.connection.settimeout(None)
        target = self._target()
        request = urllib.request.Request(
            target,
            data=body if body else None,
            # The session id is stamped on the request that goes to the
            # auditor, and nowhere else: it is how a run is attributed, and
            # it is not the model provider's business.
            headers=self._forward_headers(stamped=self._is_messages_path()),
            method=method,
        )
        try:
            response = _opener().open(request, timeout=self.read_timeout)
        except urllib.error.HTTPError as error:
            payload = error.read()
            self.send_response(error.code)
            self.send_header("content-type", error.headers.get("content-type", "application/json"))
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        except (urllib.error.URLError, OSError) as error:
            payload = json.dumps(
                {"type": "error", "error": {"type": "monolith_upstream_unreachable", "message": str(error)}}
            ).encode("utf-8")
            self.send_response(502)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        with response:
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() in HOP_BY_HOP or key.lower() == "content-type":
                    continue
                self.send_header(key, value)
            self.send_header("content-type", response.headers.get("content-type", "text/event-stream"))
            # The answer is a stream, so the framing has to be a stream too.
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                self._write_chunk(chunk)
            self._write_chunk(b"")

    def _write_chunk(self, data: bytes) -> None:
        if not data:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        self.wfile.write(f"{len(data):X}\r\n".encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def _refuse(self, status: int, message: str) -> None:
        """Answer without forwarding, and close: the body was not read, so
        the connection cannot carry another request."""
        payload = json.dumps(
            {"type": "error", "error": {"type": "monolith_request_refused", "message": message}}
        ).encode("utf-8")
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
        except OSError:
            pass

    def do_POST(self):  # noqa: N802 - stdlib signature
        self._proxy("POST")

    def do_GET(self):  # noqa: N802 - stdlib signature
        self._proxy("GET")


class _Injector:
    def __init__(self, trace_audit_url: str, upstream_url: str, correlation: dict[str, str]):
        handler = type(
            "BoundInjectorHandler",
            (_InjectorHandler,),
            {
                "trace_audit_url": trace_audit_url,
                "upstream_url": upstream_url,
                "correlation": correlation,
            },
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> _Injector:
        self.thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


# --- MCP configuration -----------------------------------------------------


def discover_mcp_servers(cwd: Path) -> dict[str, dict]:
    """The MCP servers the agent would have started on its own.

    Two places hold them: the project's ``.mcp.json`` and the user's
    ``~/.claude.json`` (which keeps a global set and a per-project one).
    """
    servers: dict[str, dict] = {}

    project_config = cwd / ".mcp.json"
    if project_config.is_file():
        try:
            data = json.loads(project_config.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for name, spec in (data.get("mcpServers") or {}).items():
            if isinstance(spec, dict):
                servers[name] = spec

    user_config = Path.home() / ".claude.json"
    if user_config.is_file():
        try:
            data = json.loads(user_config.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for source in (
            data.get("mcpServers") or {},
            ((data.get("projects") or {}).get(str(cwd)) or {}).get("mcpServers") or {},
        ):
            for name, spec in source.items():
                if isinstance(spec, dict) and name not in servers:
                    servers[name] = spec
    return servers


def find_mcp_shield() -> Path | None:
    """The MCP-Shield binary the wrapped servers are launched through."""
    explicit = os.environ.get("MONOLITH_MCP_SHIELD_BIN")
    if explicit:
        candidate = Path(explicit)
        return candidate if candidate.is_file() else None
    for profile in ("release", "debug"):
        for name in ("mcp-shield", "mcp-shield.exe"):
            candidate = REPO_ROOT / "mcp-shield" / "target" / profile / name
            if candidate.is_file():
                return candidate
    found = shutil.which("mcp-shield")
    return Path(found) if found else None


def build_shield_env(
    *,
    dashboard_url: str,
    workdir: Path,
    tenant_id: str,
    agent_id: str,
    session_id: str,
    event_token: str | None = None,
    shield_key: str | None = None,
    allow_insecure_dashboard: bool = False,
) -> dict[str, str]:
    """The environment every shielded MCP server is started with.

    The shield applies the same transport rule the launcher does: HTTPS
    everywhere, plain HTTP only to loopback unless the operator says the
    network is trusted. The operator's answer lives in the same .env file
    the launcher reads, so the shield has to be told it — otherwise the
    tool layer silently stops delivering while the launcher's own report
    still works.
    """
    env = {
        "MONOLITH_DASHBOARD_URL": dashboard_url.rstrip("/") + "/api/ingest",
        "MONOLITH_EVENT_OUTBOX_PATH": str(workdir / "mcp-shield-outbox.jsonl"),
        "MCP_SHIELD_BASELINE": str(workdir / "mcp-shield-baseline.json"),
        "MCP_SHIELD_MODE": "enforce",
        "MONOLITH_TENANT_ID": tenant_id,
        "MONOLITH_AGENT_ID": agent_id,
        "MONOLITH_SESSION_ID": session_id,
    }
    if event_token:
        env["MONOLITH_EVENT_TOKEN"] = event_token
    if shield_key:
        env["MCP_SHIELD_KEY"] = shield_key
    if allow_insecure_dashboard:
        env["MONOLITH_ALLOW_INSECURE_DASHBOARD"] = "true"
    return env


def build_mcp_config(
    servers: dict[str, dict],
    *,
    shield: Path | None,
    env: dict[str, str],
    vector_anchor_url: str,
    python: str,
) -> dict:
    """Rewrite the agent's MCP configuration so every server is shielded."""
    wrapped: dict[str, dict] = {}

    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = spec.get("command")
        if not isinstance(command, str) or not command:
            # A remote (SSE/HTTP) server is not something a stdio proxy can
            # wrap. It is left exactly as it was rather than silently
            # dropped.
            wrapped[name] = spec
            continue
        args = spec.get("args")
        args = [str(arg) for arg in args] if isinstance(args, list) else []
        server_env = spec.get("env")
        server_env = {str(k): str(v) for k, v in server_env.items()} if isinstance(server_env, dict) else {}
        server_env.update(env)
        if shield is None:
            wrapped[name] = {"command": command, "args": args, "env": server_env}
            continue
        wrapped[name] = {
            "command": str(shield),
            "args": [command, *args],
            "env": server_env,
        }

    vector_env = dict(env)
    vector_env["MONOLITH_VECTOR_ANCHOR_URL"] = vector_anchor_url
    vector_command = str(python)
    vector_args = [str(REPO_ROOT / "vector-anchor" / "src" / "mcp_server.py")]
    if shield is None:
        wrapped["vector-anchor"] = {
            "command": vector_command,
            "args": vector_args,
            "env": vector_env,
        }
    else:
        wrapped["vector-anchor"] = {
            "command": str(shield),
            "args": [vector_command, *vector_args],
            "env": vector_env,
        }
    return {"mcpServers": wrapped}


# --- reporting -------------------------------------------------------------


def print_session_report(
    dashboard_url: str,
    session_id: str,
    operator_token: str | None,
    allow_insecure: bool = False,
) -> None:
    if not operator_token:
        print(
            "\n  No operator token was available, so the session report was skipped.\n"
            f"  Session id: {session_id}\n"
            f"  Look it up at {dashboard_url} (the console asks for a sign-in)."
        )
        return
    if not credential_transport_is_trusted(dashboard_url, allow_insecure):
        print(
            "\n  The session report was skipped: it would send the operator token to\n"
            f"  {dashboard_url} over plain HTTP. Use HTTPS, a loopback address, or set\n"
            "  MONOLITH_ALLOW_INSECURE_DASHBOARD=true if that network is trusted.\n"
            f"  Session id: {session_id}"
        )
        return
    url = dashboard_url.rstrip("/") + f"/api/sessions/{session_id}"
    # A plain-HTTP dashboard means the operator token travels in cleartext,
    # and urllib would hand the request to an ambient http_proxy on the way
    # out — to a host that is not the loopback address the guard just
    # approved. An HTTPS request is tunnelled through the proxy instead,
    # which cannot read the token, so the proxy is left alone there.
    plain_http = urllib.parse.urlparse(url).scheme == "http"
    try:
        report = http_get_json(
            url,
            timeout=15.0,
            headers={"authorization": f"Bearer {operator_token}"},
            use_proxy=not plain_http,
        )
    except urllib.error.HTTPError as error:
        print(f"\n  The session report could not be read: HTTP {error.code}.")
        return
    except (urllib.error.URLError, OSError, ValueError) as error:
        print(f"\n  The session report could not be read: {error}")
        return

    summary = report.get("summary") or {}
    by_module = summary.get("by_module") or {}
    by_severity = summary.get("by_severity") or {}
    print("\n  Session report")
    print("  --------------")
    print(f"  session    {session_id}")
    total = summary.get("total", 0)
    counted = summary.get("counted", total)
    print(f"  events     {total}")
    if summary.get("truncated"):
        # The session is larger than one page, and the counts below cover
        # the page, not the session. Saying so beats a ratio that reads as
        # if it covered everything.
        print(f"             (the counts below cover the first {counted} of them)")
    print(
        "  severity  "
        f"critical {by_severity.get('critical', 0)}"
        f"   warning {by_severity.get('warning', 0)}"
        f"   info {by_severity.get('info', 0)}"
    )
    if by_module:
        print("  layers    " + "   ".join(f"{module} {count}" for module, count in sorted(by_module.items())))
    print(
        f"  detections {summary.get('detections', 0)}"
        f"   blocks {summary.get('blocks', 0)}"
        f"   quarantines {summary.get('quarantines', 0)}"
        f"   revocations {summary.get('revocations', 0)}"
    )
    if summary.get("revocations"):
        print("\n  This session was REVOKED by the cross-layer circuit breaker.")
    print(f"\n  Open the console at {dashboard_url} to see the full timeline.\n")


# --- the command -----------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="monolith wrap",
        description="Run an agent inside the Project Black Monolith defense stack.",
    )
    parser.add_argument(
        "--claude",
        action="store_true",
        help="run Claude Code under the gateway (the default agent)",
    )
    parser.add_argument(
        "--agent",
        default="claude",
        help="the agent command to run (default: claude)",
    )
    parser.add_argument(
        "--no-mcp",
        action="store_true",
        help="do not wrap the agent's own MCP servers; only add the memory layer",
    )
    parser.add_argument(
        "--mcp-config",
        action="append",
        default=[],
        help="an extra MCP config file to wrap (repeatable)",
    )
    parser.add_argument("--agent-id", default=None, help="the agent identity to record")
    parser.add_argument("--tenant-id", default=None, help="the tenant to record")
    parser.add_argument(
        "--session-id",
        default=None,
        help="use this session id instead of minting one (lets a caller resume a session)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="skip the session report at the end",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print what would happen and exit",
    )
    parser.add_argument(
        "agent_args",
        nargs=argparse.REMAINDER,
        help="arguments passed through to the agent",
    )
    args = parser.parse_args(argv)

    dotenv = load_dotenv(REPO_ROOT / ".env")
    dashboard_url = resolve_setting("MONOLITH_DASHBOARD_API_URL", dotenv, DEFAULT_DASHBOARD_URL)
    vector_anchor_url = resolve_setting("MONOLITH_VECTOR_ANCHOR_URL", dotenv, DEFAULT_VECTOR_ANCHOR_URL)
    trace_audit_url = resolve_setting("MONOLITH_TRACE_AUDIT_URL", dotenv, DEFAULT_TRACE_AUDIT_URL)
    tenant_id = args.tenant_id or resolve_setting("MONOLITH_TENANT_ID", dotenv, "default")
    agent_id = args.agent_id or resolve_setting("MONOLITH_AGENT_ID", dotenv, "claude-code")
    operator_token = resolve_setting("MONOLITH_OPERATOR_TOKEN", dotenv)
    event_token = resolve_setting("MONOLITH_EVENT_TOKEN_MCP_SHIELD", dotenv)
    shield_key = resolve_setting("MCP_SHIELD_KEY", dotenv)
    # One answer to "is the network trusted?", read once and used by both
    # the launcher's own report and the tool layer's delivery.
    allow_insecure_dashboard = (
        resolve_setting("MONOLITH_ALLOW_INSECURE_DASHBOARD", dotenv) == "true"
    )

    # The upstream the agent was already pointed at. The injector sends
    # everything that is not /v1/messages straight there.
    upstream_url = os.environ.get("ANTHROPIC_BASE_URL") or DEFAULT_UPSTREAM_URL
    if upstream_url.rstrip("/").endswith("/v1"):
        upstream_url = upstream_url.rstrip("/")[: -len("/v1")]

    # The session id is the key every layer correlates on, so it is also the
    # key somebody would need in order to file events into this run's ledger.
    # A timestamp and a pid are guessable by anything else on the machine, so
    # the id carries 122 bits of randomness instead: a caller that cannot
    # guess it cannot pretend to be this run.
    session_id = args.session_id or mint_session_id()
    correlation = {
        "X-Monolith-Session-Id": session_id,
        "X-Monolith-Agent-Id": agent_id,
        "X-Monolith-Tenant-Id": tenant_id,
    }

    print("  Project Black Monolith - agent gateway")
    print(f"  session id  {session_id}")
    print(f"  agent       {agent_id}   tenant {tenant_id}")

    # --- preflight -------------------------------------------------------
    problems: list[str] = []
    if not service_healthy(dashboard_url.rstrip("/") + "/api/ingest"):
        problems.append(f"the dashboard is not answering at {dashboard_url}")
    if not service_healthy(vector_anchor_url.rstrip("/") + "/health"):
        problems.append(f"VectorAnchor is not answering at {vector_anchor_url}")
    if not service_healthy(trace_audit_url.rstrip("/") + "/health"):
        problems.append(f"TraceAudit is not answering at {trace_audit_url}")
    shield = find_mcp_shield()
    if shield is None and not args.no_mcp:
        problems.append(
            "the MCP-Shield binary was not found - build it with "
            "`cargo build --release` in mcp-shield/, or set MONOLITH_MCP_SHIELD_BIN"
        )
    if not event_token:
        problems.append(
            "MONOLITH_EVENT_TOKEN_MCP_SHIELD was not found (the .env file next to "
            "the stack carries it) - the tool layer would have nowhere to report"
        )
    if problems:
        print("\n  The stack is not ready:")
        for problem in problems:
            print(f"    - {problem}")
        print("\n  Start it with `docker compose up -d --build` and try again.\n")
        return 2

    # --- the MCP configuration -------------------------------------------
    servers: dict[str, dict] = {}
    if not args.no_mcp:
        servers = discover_mcp_servers(Path.cwd())
        for extra in args.mcp_config:
            path = Path(extra)
            if not path.is_file():
                print(f"  The MCP config {extra} does not exist.")
                return 2
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                print(f"  The MCP config {extra} could not be read: {error}")
                return 2
            for name, spec in (data.get("mcpServers") or {}).items():
                if isinstance(spec, dict):
                    servers[name] = spec

    workdir = Path(tempfile.mkdtemp(prefix="monolith-wrap-"))
    shield_env = build_shield_env(
        dashboard_url=dashboard_url,
        workdir=workdir,
        tenant_id=tenant_id,
        agent_id=agent_id,
        session_id=session_id,
        event_token=event_token,
        shield_key=shield_key,
        allow_insecure_dashboard=allow_insecure_dashboard,
    )

    config = build_mcp_config(
        servers,
        shield=shield,
        env=shield_env,
        vector_anchor_url=vector_anchor_url,
        python=sys.executable,
    )
    config_path = workdir / "mcp-config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print(f"  tool layer {len(config['mcpServers'])} MCP server(s) through MCP-Shield")
    print(f"  memory     VectorAnchor at {vector_anchor_url}")
    print(f"  reasoning  TraceAudit at {trace_audit_url}")

    if args.plan:
        print(f"\n  The MCP configuration would be written to {config_path}:\n")
        print(json.dumps(redact_config_secrets(config), indent=2))
        print("\n  (environment values are redacted; the file on disk carries the real ones)")
        shutil.rmtree(workdir, ignore_errors=True)
        return 0

    # --- run the agent ---------------------------------------------------
    agent_command = shutil.which(args.agent) or args.agent
    agent_args = list(args.agent_args)
    if agent_args and agent_args[0] == "--":
        agent_args = agent_args[1:]

    child_env = dict(os.environ)
    child_env["ANTHROPIC_BASE_URL"] = ""  # replaced below, once the port is known

    with _Injector(trace_audit_url, upstream_url, correlation) as injector:
        child_env["ANTHROPIC_BASE_URL"] = injector.base_url
        # The MCP flags go after the agent's own arguments, not before: an
        # agent that takes a script path would otherwise have its flags read
        # as the interpreter's.
        command = [agent_command, *agent_args, "--mcp-config", str(config_path), "--strict-mcp-config"]
        print(f"  running    {agent_command} {' '.join(agent_args)}".rstrip())
        print(f"  base url   {injector.base_url} -> {trace_audit_url}\n")
        try:
            completed = subprocess.run(command, env=child_env, check=False)
            exit_code = completed.returncode
        except FileNotFoundError:
            print(f"  The agent command {args.agent!r} was not found on PATH.")
            exit_code = 127
        except KeyboardInterrupt:
            exit_code = 130

    # The tool layer's shield drains its spool as it exits, which happens
    # after the agent is gone. Give it that moment before the spool goes
    # away with the work directory.
    spool_path = workdir / "mcp-shield-outbox.jsonl"
    if wait_for_spool_drain(spool_path):
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(
            f"\n  The tool layer still had undelivered events in {spool_path}.\n"
            "  The directory was left in place: nothing was discarded. To deliver\n"
            "  them, point MCP-Shield at that path (MONOLITH_EVENT_OUTBOX_PATH) and\n"
            "  start it once: it drains the backlog on startup."
        )

    if not args.no_report:
        print_session_report(
            dashboard_url,
            session_id,
            operator_token,
            allow_insecure=allow_insecure_dashboard,
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
