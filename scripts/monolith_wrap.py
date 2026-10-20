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
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
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


def http_get_json(url: str, timeout: float = 5.0, headers: dict[str, str] | None = None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=timeout) as response:
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

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        sys.stderr.write("[injector] " + (fmt % args) + "\n")

    def _forward_headers(self) -> dict[str, str]:
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP
        }
        headers["accept-encoding"] = "identity"
        headers.update(self.correlation)
        return headers

    def _target(self) -> str:
        path = self.path.split("?", 1)[0].rstrip("/")
        if path == "/v1/messages":
            return self.trace_audit_url.rstrip("/") + "/v1/messages"
        return self.upstream_url.rstrip("/") + self.path

    def _proxy(self, method: str) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        target = self._target()
        request = urllib.request.Request(
            target,
            data=body if body else None,
            headers=self._forward_headers(),
            method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=self.read_timeout)
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

    def __enter__(self) -> "_Injector":
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


def print_session_report(dashboard_url: str, session_id: str, operator_token: str | None) -> None:
    if not operator_token:
        print(
            "\n  No operator token was available, so the session report was skipped.\n"
            f"  Session id: {session_id}\n"
            f"  Look it up at {dashboard_url} (the console asks for a sign-in)."
        )
        return
    url = dashboard_url.rstrip("/") + f"/api/sessions/{session_id}"
    try:
        report = http_get_json(
            url,
            timeout=15.0,
            headers={"authorization": f"Bearer {operator_token}"},
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
    print(f"  --------------")
    print(f"  session    {session_id}")
    print(f"  events     {summary.get('total', 0)}")
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

    # The upstream the agent was already pointed at. The injector sends
    # everything that is not /v1/messages straight there.
    upstream_url = os.environ.get("ANTHROPIC_BASE_URL") or DEFAULT_UPSTREAM_URL
    if upstream_url.rstrip("/").endswith("/v1"):
        upstream_url = upstream_url.rstrip("/")[: -len("/v1")]

    session_id = args.session_id or f"monolith-{int(time.time() * 1000)}-{os.getpid():x}"
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
    shield_env = {
        "MONOLITH_DASHBOARD_URL": dashboard_url.rstrip("/") + "/api/ingest",
        "MONOLITH_EVENT_OUTBOX_PATH": str(workdir / "mcp-shield-outbox.jsonl"),
        "MCP_SHIELD_BASELINE": str(workdir / "mcp-shield-baseline.json"),
        "MCP_SHIELD_MODE": "enforce",
        "MONOLITH_TENANT_ID": tenant_id,
        "MONOLITH_AGENT_ID": agent_id,
        "MONOLITH_SESSION_ID": session_id,
    }
    if event_token:
        shield_env["MONOLITH_EVENT_TOKEN"] = event_token
    if shield_key:
        shield_env["MCP_SHIELD_KEY"] = shield_key

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
        print(json.dumps(config, indent=2))
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

    shutil.rmtree(workdir, ignore_errors=True)

    if not args.no_report:
        print_session_report(dashboard_url, session_id, operator_token)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
