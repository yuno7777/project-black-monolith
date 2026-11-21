"""Exercise the acceptance CLI against a native dashboard and a loopback GitHub fixture."""

import hashlib
import io
import json
import secrets
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch
from uuid import UUID

import verify_github_pilot as verifier
from run_local_demo import ROOT, Runner, wait_health

REPOSITORY = "pilot-fixture/dedicated"
ISSUE_PATH = f"https://api.github.com/repos/{REPOSITORY}/issues/"
ADD_LABEL = "pilot-add"
REMOVE_LABEL = "pilot-remove"


def github_handler(token, labels, comments, writes):
    class GitHub(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def respond(self, value, status=200):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            if self.headers.get("Authorization") == f"Bearer {token}":
                return True
            self.respond({"error": "unexpected fixture token"}, 401)
            return False

        def issue(self):
            return {"number": 1, "title": "Acceptance fixture", "body": "",
                    "labels": [{"name": label} for label in sorted(labels)]}

        def do_GET(self):
            if not self.authorized():
                return
            if self.path == "/1":
                self.respond(self.issue())
            elif self.path == "/1/comments?per_page=100&page=1":
                self.respond(comments)
            else:
                self.respond({"error": "unexpected fixture read"}, 404)

        def do_POST(self):
            if not self.authorized():
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/1/comments":
                writes.append("reply")
                comment = {"id": len(comments) + 1, "body": body["body"]}
                comments.append(comment)
                self.respond(comment, 201)
            elif self.path == "/1/labels" and body == {"labels": [ADD_LABEL]}:
                writes.append("add_label")
                labels.add(ADD_LABEL)
                self.respond(self.issue()["labels"])
            else:
                self.respond({"error": "unexpected fixture write"}, 422)

        def do_DELETE(self):
            if not self.authorized():
                return
            if self.path == f"/1/labels/{REMOVE_LABEL}" and REMOVE_LABEL in labels:
                writes.append("remove_label")
                labels.remove(REMOVE_LABEL)
                self.respond(self.issue()["labels"])
            else:
                self.respond({"error": "unexpected fixture removal"}, 404)

    return GitHub


def exercise(env, logs: Path, port: int):
    """Run against the migrated disposable database created by native_smoke.py."""
    logs.mkdir()
    dashboard = ROOT / "dashboard"
    node = dashboard / "node_modules/next/dist/bin/next"
    fixture = ROOT / "scripts/fixtures/pilot_github_redirect.mjs"
    workload, operator, github = (secrets.token_urlsafe(32) for _ in range(3))
    tenant = "pilot-smoke-" + secrets.token_hex(6)
    labels, comments, writes = {REMOVE_LABEL}, [], []
    dashboard_url = f"http://127.0.0.1:{port}"
    runner = Runner(logs)
    with ThreadingHTTPServer(("127.0.0.1", 0), github_handler(github, labels, comments, writes)) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        fixture_url = f"http://127.0.0.1:{server.server_port}/"
        try:
            process = runner.start("dashboard", ["node", str(node), "start", "-H", "127.0.0.1", "-p", str(port)], dashboard, {
                **env,
                "MONOLITH_TENANT_ID": tenant,
                "MONOLITH_DISABLE_AUTH": "false",
                "MONOLITH_GITHUB_REPOSITORY": REPOSITORY,
                "MONOLITH_GITHUB_TOKEN": github,
                "MONOLITH_PILOT_FIXTURE_URL": fixture_url,
                "MONOLITH_WORKLOAD_GRANTS_JSON": json.dumps([{
                    "agent_id": "pilot-agent", "session_id": "acceptance-run",
                    "token_sha256": hashlib.sha256(workload.encode()).hexdigest(),
                }]),
                "OPERATOR_TOKENS_JSON": json.dumps({"pilot-reviewer": {"token": operator, "role": "analyst", "tenant_id": tenant}}),
                "NODE_OPTIONS": f'--import="{fixture.as_uri()}"',
            })
            wait_health(dashboard_url + "/api/ingest", process)
            check_acceptance(env, logs, dashboard_url, fixture_url, workload, operator, github, comments, writes)
        finally:
            runner.close()
            server.shutdown()
            thread.join()
    print("Verified the acceptance CLI and evidence against the dashboard and PostgreSQL with loopback GitHub.")


def check_acceptance(env, logs, dashboard_url, fixture_url, workload, operator, github, comments, writes):
    state_path = logs / "state.json"
    common = ["--test-repository", REPOSITORY, "--issue", "1", "--state", str(state_path)]
    settings = {
        "MONOLITH_DASHBOARD_API_URL": dashboard_url, "MONOLITH_VERIFY_GITHUB_TOKEN": github,
        "MONOLITH_WORKLOAD_TOKEN": workload, "MONOLITH_OPERATOR_TOKEN": operator,
    }
    original_request = verifier.request

    def route(url, *args, **kwargs):
        if url.startswith(ISSUE_PATH):
            url = fixture_url + url.removeprefix(ISSUE_PATH)
        elif not url.startswith(dashboard_url + "/api/github/"):
            raise RuntimeError("Unexpected destination in local pilot verification")
        return original_request(url, *args, **kwargs)

    def run_cli(phase, *options, expected=0):
        with (
            patch.dict("os.environ", settings), patch.object(verifier, "request", route),
            patch.object(sys, "argv", ["verify_github_pilot.py", phase, *common, *options]),
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors,
        ):
            status = verifier.main()
        verifier.require(status == expected, f"Unexpected {phase} exit code {status}. {errors.getvalue().strip()}")
        return errors.getvalue()

    run_cli("prepare", "--label-to-add", ADD_LABEL, "--label-to-remove", REMOVE_LABEL)
    drafts = json.loads(state_path.read_text(encoding="utf-8"))["drafts"]
    verifier.require(not writes and len(drafts) == 6, "Preparation must queue six drafts and send nothing.")

    def decide(name, decision):
        draft = drafts[name]
        return original_request(f"{dashboard_url}/api/github/triage/{draft['id']}", {"Authorization": f"Bearer {operator}"},
                                payload={"decision": decision, "digest": draft["digest"]})

    expected_writes = ["reply", "add_label", "remove_label"]
    for name in expected_writes:
        verifier.require(decide(name, "approve")["action"]["status"] == "succeeded", f"Expected {name} to succeed.")
    verifier.require(decide("denied", "deny")["action"]["status"] == "denied", "Expected denial to persist.")
    verifier.require(decide("revoked", "revoke_session")["session"]["revoked_at"], "Expected revocation to persist.")

    immediate = logs / "immediate.json"
    expired = logs / "expired.json"
    run_cli("check-now", "--evidence", str(immediate))
    report = json.loads(immediate.read_text(encoding="utf-8"))
    verifier.require(report["actions"]["revoked"]["status"] == "revoked", "Expected revoked evidence.")
    error = run_cli("check-expired", "--evidence", str(expired), expected=1)
    verifier.require("passes its deadline" in error and not expired.exists(), "An early expiration check must leave no evidence.")

    target = UUID(drafts["expired"]["id"])
    postgres = subprocess.run(
        ["psql", env["DATABASE_ADMIN_URL"], "-X", "-v", "ON_ERROR_STOP=1", "-c",
         f"update monolith.github_triage_actions set expires_at = now() where id = '{target}'"],
        check=True, env=env, capture_output=True, text=True, timeout=15,
    )
    verifier.require(postgres.stdout.strip() == "UPDATE 1", "Expiration fixture did not update one action.")
    run_cli("check-expired", "--evidence", str(expired))
    report = json.loads(expired.read_text(encoding="utf-8"))
    verifier.require(report["actions"]["expired"]["status"] == "expired", "Expected expired evidence.")
    serialized = immediate.read_text(encoding="utf-8") + expired.read_text(encoding="utf-8")
    verifier.require(not any(secret in serialized for secret in (github, workload, operator, drafts["reply"]["value"])),
                     "Evidence leaked a credential or reply text.")
    comments.append(comments[0])
    duplicate = logs / "duplicate.json"
    error = run_cli("check-expired", "--evidence", str(duplicate), expected=1)
    verifier.require("found 2" in error and not duplicate.exists(), "A duplicate comment must leave no evidence.")
    verifier.require(writes == expected_writes, "The fixture received a write outside the three approved actions.")
