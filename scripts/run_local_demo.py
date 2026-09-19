"""Run the local demo without Docker or Bash on Windows, Linux, and macOS."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_env(path: Path, inherited: dict[str, str]) -> dict[str, str]:
    """Read literal KEY=value entries, never execute shell code or expand values."""
    values = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"Invalid .env entry at line {number}")
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError(f"Unclosed quote at .env line {number}")
            value = value[1:-1]
        values[key] = value
    return values | inherited


def configure(env: dict[str, str], ports: list[int]) -> dict[str, str]:
    required = [
        "MONOLITH_TENANT_ID",
        "MONOLITH_OPERATOR_NAME",
        "MONOLITH_OPERATOR_TOKEN",
        "MONOLITH_ADMIN_TOKEN",
        "MCP_SHIELD_KEY",
        "MONOLITH_DATABASE_RUNTIME_PASSWORD",
    ]
    modules = ("mcp-shield", "vector-anchor", "trace-audit")
    token_names = ["MONOLITH_EVENT_TOKEN_" + m.upper().replace("-", "_") for m in modules]
    required += token_names
    if not env.get("DATABASE_ADMIN_URL"):
        required.append("MONOLITH_POSTGRES_PASSWORD")
    missing = [name for name in required if not env.get(name)]
    if missing:
        raise ValueError("Missing settings: " + ", ".join(missing))
    env = env.copy()
    tenant = env["MONOLITH_TENANT_ID"]
    env["EVENT_INGEST_TOKENS_JSON"] = json.dumps(
        {tenant: {module: env[name] for module, name in zip(modules, token_names, strict=True)}}
    )
    env["OPERATOR_TOKENS_JSON"] = json.dumps(
        {
            env["MONOLITH_OPERATOR_NAME"]: {
                "token": env["MONOLITH_OPERATOR_TOKEN"],
                "role": "admin",
                "tenant_id": tenant,
            }
        }
    )
    for key, user, password in (
        ("DATABASE_ADMIN_URL", "postgres", "MONOLITH_POSTGRES_PASSWORD"),
        ("DATABASE_URL", "monolith_runtime", "MONOLITH_DATABASE_RUNTIME_PASSWORD"),
    ):
        if not env.get(key):
            env[key] = (
                f"postgresql://{user}:{urllib.parse.quote(env[password], safe='')}@127.0.0.1:5432/postgres"
            )
    env.update(
        DATABASE_APP_ROLE="monolith_app",
        PYTHONUTF8="1",
        MONOLITH_MODULE_ADMIN_TOKEN=env["MONOLITH_ADMIN_TOKEN"],
        VECTOR_ANCHOR_INTERNAL_URL=f"http://127.0.0.1:{ports[1]}",
        TRACE_AUDIT_INTERNAL_URL=f"http://127.0.0.1:{ports[2]}",
        MONOLITH_DASHBOARD_URL=f"http://127.0.0.1:{ports[0]}/api/ingest",
    )
    return env


def check_ports(ports: list[int]) -> None:
    if len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("Service ports must be distinct and between 1 and 65535")
    for port in ports:
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError as error:
                raise RuntimeError(
                    f"Port {port} is unavailable; choose a different port"
                ) from error


def process_options() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def stop_process(process: subprocess.Popen) -> None:
    """Stop only the owned process tree; never kill arbitrary port listeners."""
    if os.name == "nt":
        if process.poll() is not None:
            return
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=5)
            return
        except (OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False
            )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


class Runner:
    def __init__(self, logs: Path):
        self.logs = logs
        self.children: list[subprocess.Popen] = []

    def start(
        self, name: str, command: list[str], cwd: Path, env: dict[str, str], piped: bool = False
    ) -> subprocess.Popen:
        with (self.logs / f"{name}.log").open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if piped else subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                **process_options(),
            )
        self.children.append(process)
        return process

    def run(
        self,
        name: str,
        command: list[str],
        cwd: Path,
        env: dict[str, str],
        input_text: str | None = None,
        timeout: int = 300,
    ) -> str:
        process = self.start(name, command, cwd, env, input_text is not None)
        process.communicate(input=input_text, timeout=timeout)
        if process.returncode:
            raise RuntimeError(f"{name} failed; see {self.logs / (name + '.log')}")
        return (self.logs / f"{name}.log").read_text(encoding="utf-8")

    def close(self) -> None:
        for child in reversed(self.children):
            stop_process(child)


def wait_health(url: str, process: subprocess.Popen, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Service exited before becoming healthy at {url}; inspect logs")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise RuntimeError(f"Service did not become healthy at {url}; inspect logs")


def post(url: str, payload: dict, token: str = "", context: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    for key, header in (
        ("MONOLITH_TENANT_ID", "X-Monolith-Tenant-Id"),
        ("MONOLITH_AGENT_ID", "X-Monolith-Agent-Id"),
        ("MONOLITH_SESSION_ID", "X-Monolith-Session-Id"),
    ):
        if context and context.get(key):
            headers[header] = context[key]
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def attacks(runner: Runner, env: dict[str, str], state: Path, ports: list[int]) -> None:
    shield = ROOT / "mcp-shield"
    binary = shield / "target" / "debug" / ("mcp-shield.exe" if os.name == "nt" else "mcp-shield")
    requests = (
        "\n".join(
            json.dumps(x)
            for x in [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "demo-client", "version": "0.1.0"},
                    },
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ]
        )
        + "\n"
    )
    for phase, mode in enumerate(("clean", "modified"), 1):
        output = runner.run(
            f"mcp-{phase}",
            [str(binary), sys.executable, "fixtures/fake_mcp_server.py"],
            shield,
            env
            | {
                "MCP_FIXTURE_MODE": mode,
                "MCP_SHIELD_MODE": "enforce",
                "MCP_SHIELD_FIRST_CONTACT": "trust",
                "MCP_SHIELD_BASELINE": str(state / "baseline_hashes.json"),
                "MONOLITH_EVENT_TOKEN": env["MONOLITH_EVENT_TOKEN_MCP_SHIELD"],
                "MONOLITH_EVENT_OUTBOX_PATH": str(state / "mcp-outbox.jsonl"),
            },
            requests,
        )
        responses = []
        for line in output.splitlines():
            try:
                response = json.loads(line)
            except ValueError:
                continue
            if isinstance(response, dict) and response.get("id") == 2:
                responses.append(response)
        if not responses or '"read_file"' not in json.dumps(responses):
            raise RuntimeError(f"MCP phase {phase} did not return the trusted tool")
        if "<IMPORTANT>" in json.dumps(responses):
            raise RuntimeError("MCP enforce mode forwarded the poisoned description")
        if phase == 2 and "SCHEMA MISMATCH DETECTED" not in output:
            raise RuntimeError("MCP rug pull did not trigger detection")
    vector_env = env | {"MONOLITH_SERVICE_URL": f"http://127.0.0.1:{ports[1]}"}
    for fixture, queries in (
        (
            "seed_corpus.py",
            [
                "how to compost kitchen scraps for my garden",
                "how do astronomers measure distance to a nebula",
                "how to sear a steak so the meat stays juicy",
                "how to pay off high interest credit card debt",
            ],
        ),
        (
            "inject_poison.py",
            [
                "how do I prune tomato plants in my garden",
                "what is a red giant star in a galaxy",
                "how long should I boil pasta noodles",
                "how much emergency fund and savings should I budget",
            ],
        ),
    ):
        runner.run(
            fixture, [sys.executable, "fixtures/" + fixture], ROOT / "vector-anchor", vector_env
        )
        for query in queries:
            result = post(
                vector_env["MONOLITH_SERVICE_URL"] + "/retrieve", {"query": query}, context=env
            )
    if result.get("quarantine_size", 0) < 1:
        raise RuntimeError("VectorAnchor did not quarantine the demo poison")
    for fixture in ("divergence", "pii"):
        output = runner.run(
            fixture,
            [sys.executable, "fixtures/divergence_prompt.py", fixture],
            ROOT / "trace-audit",
            env | {"MONOLITH_SERVICE_URL": f"http://127.0.0.1:{ports[2]}"},
        )
        expected = "terminated=True" if fixture == "divergence" else "PII REDACTED"
        if expected not in output:
            raise RuntimeError(f"TraceAudit {fixture} fixture did not trigger detection")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dash-port", type=int)
    parser.add_argument("--va-port", type=int)
    parser.add_argument("--ta-port", type=int)
    parser.add_argument("--no-hold", action="store_true", help="stop after running fixtures")
    parser.add_argument("--skip-attacks", action="store_true", help="start services only")
    parser.add_argument(
        "--skip-build", action="store_true", help="use already built dashboard and MCP binary"
    )
    parser.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    args = parser.parse_args()
    if args.backend == "ollama" and not args.skip_attacks:
        parser.error(
            "Real-model startup uses --skip-attacks; synthetic detector assertions require mock"
        )
    runner = None
    try:
        env = load_env(ROOT / ".env", dict(os.environ))
        ports = [
            arg if arg is not None else int(env.get(key, default))
            for arg, key, default in (
                (args.dash_port, "DASH_PORT", "3000"),
                (args.va_port, "VA_PORT", "8001"),
                (args.ta_port, "TA_PORT", "8002"),
            )
        ]
        check_ports(ports)
        env = configure(env, ports)
        env.setdefault("MONOLITH_SESSION_ID", "demo-" + uuid.uuid4().hex)
        env.setdefault("MONOLITH_AGENT_ID", "native-demo-agent")
        for executable in ("node", "psql") + (() if args.skip_attacks else ("cargo",)):
            if not shutil.which(executable):
                raise RuntimeError(f"Required executable missing from PATH: {executable}")
        next_cli = ROOT / "dashboard/node_modules/next/dist/bin/next"
        if not next_cli.is_file():
            raise RuntimeError("Install dashboard dependencies first: cd dashboard then npm ci")
        # Run Node's JS entry point directly, avoiding npm.cmd / shell quoting on Windows.
        node = shutil.which("node")
        state = Path(tempfile.mkdtemp(prefix="monolith-demo-"))
        (state / "demo-state.json").write_text(
            json.dumps(
                {
                    "kind": "monolith-local-demo",
                    "session_id": env["MONOLITH_SESSION_ID"],
                    "ports": ports,
                }
            ),
            encoding="utf-8",
        )
        runner = Runner(state)
        print(f"Demo logs and state: {state}", flush=True)
        # Reuse the canonical bootstrap SQL without requiring Bash on the host.
        bootstrap = (ROOT / "supabase/bootstrap/001-runtime-role.sh").read_text(encoding="utf-8")
        sql = bootstrap.split("<<'SQL'\n", 1)[1].rsplit("\nSQL", 1)[0]
        runner.run(
            "bootstrap",
            [
                shutil.which("psql"),
                "--no-psqlrc",
                "--set=ON_ERROR_STOP=1",
                "--set=runtime_password=" + env["MONOLITH_DATABASE_RUNTIME_PASSWORD"],
            ],
            ROOT,
            env | {"PGDATABASE": env["DATABASE_ADMIN_URL"]},
            sql,
        )
        dashboard = ROOT / "dashboard"
        runner.run(
            "migrations",
            [node, "scripts/migrate.mjs"],
            dashboard,
            env
            | {
                "DATABASE_URL": env["DATABASE_ADMIN_URL"],
                "DATABASE_MIGRATIONS_DIR": str(ROOT / "supabase/migrations"),
            },
        )
        if not args.skip_build:
            runner.run("build", [node, str(next_cli), "build"], dashboard, env, timeout=900)
        if not args.skip_attacks and not args.skip_build:
            runner.run(
                "cargo-build",
                [shutil.which("cargo"), "build", "--locked"],
                ROOT / "mcp-shield",
                env,
                timeout=900,
            )
        process = runner.start(
            "dashboard",
            [node, str(next_cli), "start", "-H", "127.0.0.1", "-p", str(ports[0])],
            dashboard,
            env,
        )
        services = [process]
        wait_health(f"http://127.0.0.1:{ports[0]}/api/ingest", process)
        if env.get("MONOLITH_ALERT_WEBHOOK_URL") or env.get("MONOLITH_ALERT_WEBHOOK_SECRET"):
            services.append(
                runner.start("alerts", [node, "scripts/dispatch-alerts.mjs"], dashboard, env)
            )
        for module, port in zip(("vector-anchor", "trace-audit"), ports[1:], strict=True):
            module_env = env | {
                "MONOLITH_EVENT_TOKEN": env[
                    "MONOLITH_EVENT_TOKEN_" + module.upper().replace("-", "_")
                ],
                "MONOLITH_EVENT_OUTBOX_PATH": str(state / (module + "-outbox.db")),
                "MONOLITH_DETECTOR_STATE_PATH": str(state / "vector-state.json"),
                "MONOLITH_CHROMA_PATH": str(state / "chroma"),
                "MONOLITH_EMBEDDING": "hash",
                "MONOLITH_MODEL_BACKEND": args.backend,
                "MONOLITH_BASELINE_PATH": str(state / "baseline.json"),
            }
            if module == "trace-audit":
                runner.run(
                    "baseline",
                    [sys.executable, "fixtures/baseline_capture.py"],
                    ROOT / module,
                    module_env,
                )
            process = runner.start(
                module,
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "src.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                ROOT / module,
                module_env,
            )
            services.append(process)
            wait_health(f"http://127.0.0.1:{port}/health", process)
        if not args.skip_attacks:
            attacks(runner, env, state, ports)
            from verify_session import verify_session

            report = verify_session(
                f"http://127.0.0.1:{ports[0]}",
                env["MONOLITH_OPERATOR_TOKEN"],
                env["MONOLITH_SESSION_ID"],
                env["MONOLITH_AGENT_ID"],
            )
            (state / "verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            print("Verified all three layers in the PostgreSQL ledger", flush=True)
            runner.run("protected-agent", [sys.executable, str(ROOT / "examples/protected_agent.py"),
                "Summarize the project note", "--note", str(ROOT / "examples/project-note.txt"),
                "--state-dir", str(state / "protected-agent"),
                "--vector-url", f"http://127.0.0.1:{ports[1]}",
                "--trace-url", f"http://127.0.0.1:{ports[2]}",
                "--dashboard-url", f"http://127.0.0.1:{ports[0]}"], ROOT, env)
        print(f"Local services ready: http://127.0.0.1:{ports[0]}", flush=True)
        if not args.no_hold and env.get("DEMO_HOLD", "1") != "0":
            print("Press Ctrl-C to stop services.", flush=True)
            while True:
                if any(service.poll() is not None for service in services):
                    raise RuntimeError("A service exited unexpectedly; inspect logs")
                time.sleep(0.5)
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Local demo failed: {error}", file=sys.stderr)
        return 1
    finally:
        if runner:
            runner.close()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    raise SystemExit(main())
