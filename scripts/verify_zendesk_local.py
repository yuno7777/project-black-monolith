"""Verify approved replies against the production dashboard and Zendesk API fixture."""

import hashlib
import io
import json
import secrets
import threading
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from uuid import uuid4

import verify_zendesk_pilot
from business_practice_connector import ConnectorServer
from business_zendesk_connector import DispatchLedger, Zendesk
from fixtures.zendesk_fixture import REPLY, TICKET, ZendeskFixture
from run_local_demo import ROOT, Runner, wait_health
from verify_github_pilot import request, require


def exercise(env, logs, port):
    logs.mkdir()
    tenant = "zendesk-" + secrets.token_hex(6)
    agent = "support-pilot"
    token, operator, connector_token = (secrets.token_urlsafe(32) for _ in range(3))
    operator_headers = {"Authorization": "Bearer " + operator}
    provider = ZendeskFixture()
    zendesk = Zendesk("pilot-sandbox", "zendesk-token-for-testing", {TICKET})
    zendesk.opener = provider
    ledger = DispatchLedger(logs / "receipts.sqlite3", tenant, zendesk)
    runner = Runner(logs)
    dashboard = ROOT / "dashboard"
    base = f"http://127.0.0.1:{port}"
    with ConnectorServer(0, tenant, connector_token, ledger.dispatch) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            settings = {
                "MONOLITH_DISABLE_AUTH": "false",
                "MONOLITH_TENANT_ID": tenant,
                "OPERATOR_TOKENS_JSON": json.dumps({"reviewer": {"token": operator, "role": "admin", "tenant_id": tenant}}),
                "MONOLITH_WORKLOAD_GRANTS_JSON": json.dumps([{
                    "agent_id": agent, "session_id": "pilot", "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                }]),
                "MONOLITH_BUSINESS_REVIEWERS_JSON": json.dumps([{"tenant": tenant, "actor": "reviewer", "teams": ["support"]}]),
                "MONOLITH_BUSINESS_CONNECTORS_JSON": json.dumps([{
                    "tenant": tenant, "url": f"http://127.0.0.1:{server.server_port}/monolith", "token": connector_token,
                }]),
            }
            process = runner.start("dashboard", ["node", str(dashboard / "node_modules/next/dist/bin/next"),
                                   "start", "-H", "127.0.0.1", "-p", str(port)], dashboard, env | settings)
            wait_health(base + "/api/ingest", process)
            run_workflow(base + "/api/business", agent, token, operator_headers, ledger, provider, logs)
        finally:
            runner.close()
            server.shutdown()
            thread.join()
    print("Verified Zendesk exact reply, denial, replay refusal and reconciliation using the dashboard and local API fixture.")


def run_workflow(api, agent, token, operator, ledger, provider, logs):
    request(api + "/agents", operator, payload={
        "agentId": agent, "owner": "Support", "allowedKinds": ["customer_reply"], "paused": False, "practiceOnly": False,
    })

    def propose():
        return request(api + "/proposals", {"X-Monolith-Workload-Token": token}, expected=202, payload={
            "requestId": str(uuid4()), "caseId": "synthetic-" + uuid4().hex, "templateId": "support", "action": REPLY,
        })["decision"]

    def decide(row, decision, expected=200, **kwargs):
        return request(api + "/decisions", operator, expected=expected, payload={
            "id": row["id"], "digest": row["digest"], "decision": decision, **kwargs,
        }).get("decision")

    state_path = logs / "zendesk-state.json"
    report = logs / "zendesk-evidence.json"
    settings = {
        "MONOLITH_DASHBOARD_API_URL": api.removesuffix("/api/business"),
        "MONOLITH_WORKLOAD_TOKEN": token,
        "MONOLITH_VERIFY_ZENDESK_TOKEN": "zendesk-token-for-testing",
        "MONOLITH_OPERATOR_TOKEN": operator["Authorization"].removeprefix("Bearer "),
    }

    def run_cli(phase, *options):
        args = [phase, "--sandbox-subdomain", "pilot-sandbox", "--ticket", str(TICKET),
                "--state", str(state_path), *options]
        with (patch.dict("os.environ", settings), patch.object(verify_zendesk_pilot, "Zendesk", return_value=ledger.zendesk),
              redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors):
            result = verify_zendesk_pilot.main(args)
        return result, errors.getvalue()

    status, error = run_cli("prepare")
    require(status == 0, error)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    approved, denied = (state["decisions"][scenario] for scenario in ("approved", "denied"))
    interrupted = propose()
    require(not provider.writes, "Drafting a reply wrote to the provider.")
    confirmed = decide(approved, "approve")
    require(confirmed["status"] == "succeeded" and confirmed["reference"] == "zendesk-ticket-42-comment-51",
            "Zendesk did not confirm the approved reply.")
    decide(approved, "approve", expected=409)
    decide(denied, "deny")
    decide(denied, "approve", expected=409)
    require(len(provider.writes) == 1, "A denied or replayed decision wrote to Zendesk.")

    status, error = run_cli("check", "--evidence", str(report))
    require(status == 0, error)
    evidence = json.loads(report.read_text(encoding="utf-8"))
    require(evidence["decisions"]["approved"]["reference"] == confirmed["reference"]
            and evidence["decisions"]["denied"]["status"] == "denied", "Saved Zendesk evidence was incorrect.")
    serialized = report.read_text(encoding="utf-8")
    require(state["marker"] not in serialized and all(secret not in serialized for secret in settings.values()),
            "Saved Zendesk evidence contained credentials or reply text.")
    duplicate_report = logs / "duplicate.json"
    provider.receipts.append(provider.receipts[0])
    status, error = run_cli("check", "--evidence", str(duplicate_report))
    provider.receipts.pop()
    require(status == 1 and "exactly one" in error and not duplicate_report.exists(),
            "Duplicate Zendesk comments must not produce accepted evidence.")

    provider.fail = "lost"
    lost = decide(interrupted, "approve")
    require(lost["status"] == "uncertain", "A lost Zendesk acknowledgment must leave the decision uncertain.")
    decide(interrupted, "approve", expected=409)
    receipt = ledger.reconcile(interrupted["id"])
    require(receipt is not None and receipt["reference"] == "zendesk-ticket-42-comment-52",
            "Read-only reconciliation could not find the provider receipt.")
    resolved = decide(interrupted, "confirm", note=f"Verified provider receipt {receipt['reference']}")
    require(resolved["status"] == "succeeded", "Dashboard did not record the reconciliation.")
    expected = verify_zendesk_pilot.reply("pilot-sandbox", TICKET, state["marker"], "approved")
    require([item["comment"]["body"] for item in provider.writes] == [expected["body"], REPLY["body"]],
            "Zendesk received an extra or changed write.")
