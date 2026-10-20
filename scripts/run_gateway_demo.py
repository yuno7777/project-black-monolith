#!/usr/bin/env python3
"""The agent gateway, end to end, with no API key and no credits.

This drives the whole chain the way a real agent session would:

    agent  ->  monolith wrap  ->  TraceAudit  ->  model
                   |                                  ^
                   |                                  |
                   +-- MCP servers (through MCP-Shield)
                   |
                   +-- VectorAnchor (the memory layer)

The model is a local stub (``trace-audit/fixtures/fake_anthropic_server.py``)
that answers with a leaked credential, and the credential is AWS's own
published example key - a value that exists in the AWS documentation so that
scanners can recognise it, and which is not a credential to anything.

What the demo asserts:

  * the agent's answer never contains the credential
  * the agent's answer says it was redacted
  * the ledger holds the session's events, filed under the session id
  * the session report shows what the run tripped

Usage: python scripts/run_gateway_demo.py
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_AGENT = Path(__file__).resolve().parent / "fixtures" / "demo_agent.py"
FAKE_ANTHROPIC = REPO_ROOT / "trace-audit" / "fixtures" / "fake_anthropic_server.py"

FICTIONAL_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export "):].strip()
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    return False


def check(label: str, condition: bool, detail: str = "") -> bool:
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {label}" + (f" - {detail}" if detail else ""))
    return condition


def main() -> int:
    dotenv = load_dotenv(REPO_ROOT / ".env")
    if not dotenv.get("MONOLITH_EVENT_TOKEN_TRACE_AUDIT"):
        print("  The .env file next to the stack has no module tokens. Run scripts/generate_secrets.sh first.")
        return 2

    dashboard_url = os.environ.get("MONOLITH_DASHBOARD_API_URL", "http://127.0.0.1:3000")
    vector_anchor_url = os.environ.get("MONOLITH_VECTOR_ANCHOR_URL", "http://127.0.0.1:8001")
    operator_token = dotenv.get("MONOLITH_OPERATOR_TOKEN")

    model_port = free_port()
    audit_port = free_port()
    workdir = Path(tempfile.mkdtemp(prefix="monolith-gateway-demo-"))
    session_id = f"demo-gateway-{int(time.time())}"

    print("  Project Black Monolith - agent gateway demo")
    print(f"  session id  {session_id}")
    print()

    # --- the model ------------------------------------------------------
    model = subprocess.Popen(
        [sys.executable, str(FAKE_ANTHROPIC), "--port", str(model_port), "--mode", "secret"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # --- the reasoning layer, pointed at that model ---------------------
    audit_env = dict(os.environ)
    audit_env.update(
        {
            "MONOLITH_MODEL_BACKEND": "anthropic",
            "MONOLITH_ANTHROPIC_BASE_URL": f"http://127.0.0.1:{model_port}",
            "MONOLITH_ANTHROPIC_API_KEY": "demo-key-not-a-credential",
            "MONOLITH_BASELINE_PATH": str(workdir / "baseline.json"),
            "MONOLITH_DASHBOARD_URL": f"{dashboard_url.rstrip('/')}/api/ingest",
            "MONOLITH_EVENT_TOKEN": dotenv["MONOLITH_EVENT_TOKEN_TRACE_AUDIT"],
            "MONOLITH_EVENT_OUTBOX_PATH": str(workdir / "trace-audit-outbox.db"),
            "MONOLITH_ALLOW_INSECURE_DASHBOARD": "true",
            "MONOLITH_ADMIN_TOKEN": dotenv.get("MONOLITH_ADMIN_TOKEN", ""),
            "MONOLITH_TENANT_ID": dotenv.get("MONOLITH_TENANT_ID", "default"),
            "MONOLITH_AGENT_ID": "demo-agent",
            "PYTHONPATH": str(REPO_ROOT / "trace-audit"),
        }
    )
    audit = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.main:app", "--host", "127.0.0.1", "--port", str(audit_port)],
        cwd=str(REPO_ROOT / "trace-audit"),
        env=audit_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    failures = 0
    try:
        if not wait_for(f"http://127.0.0.1:{audit_port}/health"):
            print("  TraceAudit did not come up.")
            return 2

        # --- the agent --------------------------------------------------
        wrap_env = dict(os.environ)
        wrap_env.update(
            {
                "MONOLITH_DASHBOARD_API_URL": dashboard_url,
                "MONOLITH_VECTOR_ANCHOR_URL": vector_anchor_url,
                "MONOLITH_TRACE_AUDIT_URL": f"http://127.0.0.1:{audit_port}",
                "ANTHROPIC_BASE_URL": "https://api.anthropic.com",
                "ANTHROPIC_API_KEY": "demo-agent-key-not-a-credential",
            }
        )
        for name in ("MONOLITH_EVENT_TOKEN_MCP_SHIELD", "MONOLITH_OPERATOR_TOKEN", "MONOLITH_TENANT_ID"):
            if dotenv.get(name):
                wrap_env[name] = dotenv[name]

        print("  running the agent under the gateway")
        print()
        completed = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "monolith_wrap.py"),
                "--agent",
                sys.executable,
                "--session-id",
                session_id,
                "--agent-id",
                "demo-agent",
                "--",
                str(DEMO_AGENT),
            ],
            cwd=str(REPO_ROOT),
            env=wrap_env,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(completed.stdout)
        if completed.returncode != 0:
            sys.stderr.write(completed.stderr)

        # --- what the agent saw ----------------------------------------
        answer = ""
        if "AGENT_ANSWER_BEGIN" in completed.stdout:
            answer = completed.stdout.split("AGENT_ANSWER_BEGIN", 1)[1].split("AGENT_ANSWER_END", 1)[0]

        print()
        print("  assertions")
        failures += not check(
            "the agent never received the credential",
            FICTIONAL_AWS_KEY not in answer,
        )
        failures += not check(
            "the agent was told the credential was redacted",
            "REDACTED" in answer.upper(),
        )
        failures += not check(
            "the agent's answer still arrived",
            bool(answer.strip()),
        )

        # --- what the ledger holds -------------------------------------
        if operator_token:
            report = None
            for _ in range(20):
                try:
                    request = urllib.request.Request(
                        f"{dashboard_url.rstrip('/')}/api/sessions/{session_id}",
                        headers={"authorization": f"Bearer {operator_token}"},
                    )
                    with urllib.request.urlopen(request, timeout=10) as response:
                        report = json.loads(response.read())
                    break
                except (urllib.error.URLError, OSError, ValueError):
                    time.sleep(1)
            if report is None:
                failures += not check("the ledger returned the session report", False)
            else:
                summary = report.get("summary") or {}
                failures += not check(
                    "the ledger filed the session's events",
                    summary.get("total", 0) > 0,
                    f"{summary.get('total')} event(s)",
                )
                failures += not check(
                    "the redaction is in the ledger",
                    summary.get("by_event_type", {}).get("pii_redacted", 0) > 0,
                )
                failures += not check(
                    "the report counted the detection",
                    summary.get("detections", 0) > 0,
                    f"{summary.get('detections')} detection(s)",
                )
                print()
                print("  session report from the ledger:")
                print(json.dumps(summary, indent=2))
    finally:
        for process in (audit, model):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    print()
    if failures:
        print(f"  {failures} assertion(s) failed.")
        return 1
    print("  Every assertion passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
