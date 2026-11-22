"""Check business decisions against a production dashboard and a loopback connector."""

import hashlib
import json
import secrets
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

from monolith_wrap import _opener
from run_local_demo import ROOT, Runner, wait_health
from verify_github_pilot import request, require


def connector_handler(token, tenant, writes):
    class Connector(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            authorized = self.headers.get("Authorization") == f"Bearer {token}"
            if (self.path != "/actions" or not authorized or payload.get("tenant") != tenant
                    or not payload.get("id") or self.headers.get("Idempotency-Key") != payload["id"]):
                self.send_error(403)
                return
            writes.append(payload)
            if payload["action"].get("orderId") == "order-uncertain":
                # The provider received the action, then the connection broke.
                self.close_connection = True
                return
            result = json.dumps({"id": payload["id"], "status": "succeeded",
                                 "reference": "receipt-" + payload["id"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)

    return Connector


def exercise(env, logs, port, psql):
    logs.mkdir()
    tenant = "business-smoke-" + secrets.token_hex(6)
    agent = "returns-assistant"
    operator_accounts = {
        name: {"token": secrets.token_urlsafe(32), "role": role, "tenant_id": scope}
        for name, role, scope in [
            ("manager", "admin", tenant), ("finance-reviewer", "analyst", tenant),
            ("support-reviewer", "analyst", tenant), ("other-manager", "admin", tenant + "-other"),
            ("read-only", "viewer", tenant),
        ]
    }
    tokens = {name: {"Authorization": "Bearer " + account["token"]} for name, account in operator_accounts.items()}
    agent_token, connector_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    workload = {"X-Monolith-Workload-Token": agent_token}
    dashboard = ROOT / "dashboard"
    base = f"http://127.0.0.1:{port}"
    runner = Runner(logs)
    writes = []
    with ThreadingHTTPServer(("127.0.0.1", 0), connector_handler(connector_token, tenant, writes)) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        settings = {
            "MONOLITH_TENANT_ID": tenant,
            "MONOLITH_DISABLE_AUTH": "false",
            "MONOLITH_WORKLOAD_GRANTS_JSON": json.dumps([{
                "agent_id": agent, "session_id": "run",
                "token_sha256": hashlib.sha256(agent_token.encode()).hexdigest(),
            }]),
            "OPERATOR_TOKENS_JSON": json.dumps(operator_accounts),
            "MONOLITH_BUSINESS_CONNECTORS_JSON": json.dumps([{
                "tenant": tenant, "url": f"http://127.0.0.1:{server.server_port}/actions", "token": connector_token,
            }]),
            "MONOLITH_BUSINESS_REVIEWERS_JSON": json.dumps([
                {"tenant": tenant, "actor": "finance-reviewer", "teams": ["finance"]},
                {"tenant": tenant, "actor": "support-reviewer", "teams": ["support"]},
                {"tenant": tenant + "-other", "actor": "other-manager", "teams": ["finance"]},
            ]),
        }
        try:
            process = runner.start("business-dashboard", [
                "node", str(dashboard / "node_modules/next/dist/bin/next"), "start", "-H", "127.0.0.1", "-p", str(port),
            ], dashboard, env | settings)
            wait_health(base + "/api/ingest", process)
            check_workflow(env, psql, base + "/api/business", tenant, agent, tokens, workload, writes)
        finally:
            runner.close()
            server.shutdown()
            thread.join()
    print("Verified business refund workflow, reviewer routing, tenant isolation, revocation, and recovery with loopback provider.")


def check_workflow(env, psql, api, tenant, agent, tokens, workload, writes):
    manager = tokens["manager"]
    support = tokens["support-reviewer"]
    finance = tokens["finance-reviewer"]
    agent_record = {"agentId": agent, "owner": "Support", "allowedKinds": ["refund", "customer_reply"], "paused": False}
    refund = {"kind": "refund", "orderId": "order-test", "destination": "customer-payment-12",
              "currency": "USD", "amountMinor": 12500}
    policy = {"currency": "USD", "refundThresholdMinor": 10000, "financeTeam": "finance", "defaultTeam": "support"}

    def snapshot(auth=manager):
        return request(api, auth)

    def proposal(action, case="case-01", request_id=None, expected=202):
        response = request(api + "/proposals", workload, expected=expected, payload={
            "requestId": request_id or str(uuid4()), "caseId": case, "templateId": "refund", "action": action,
        })
        return response.get("decision")

    def review(row, auth, decision="approve", expected=200, **changes):
        result = request(api + "/decisions", auth, expected=expected, payload={
            "id": row["id"], "digest": row["digest"], "decision": decision, **changes,
        })
        return result.get("decision")

    request(api + "/agents", tokens["read-only"], payload=agent_record, expected=403)
    request(api + "/agents", manager, payload=agent_record)
    request(api + "/policies", manager, payload={"policy": policy})
    preview = request(api + "/practice", workload, payload={"templateId": "refund", "action": refund})
    require(preview["ok"] and preview["reviewerTeam"] == "finance", "Workload practice routing failed.")
    proposal(refund, expected=403)
    request(api + "/agents", manager, payload={**agent_record, "practiceOnly": False})
    before = snapshot()
    for amount, team in [(10000, "support"), (10001, "finance")]:
        result = request(api + "/practice", manager, payload={"action": {**refund, "amountMinor": amount}})
        require(result["ok"] and result["reviewerTeam"] == team, "Practice routed the threshold incorrectly.")
    require(snapshot()["decisions"] == before["decisions"] and not writes, "Practice created a decision or a write.")

    key = str(uuid4())
    first = proposal(refund, request_id=key)
    require(proposal(refund, request_id=key)["id"] == first["id"], "A proposal retry must return the same decision.")
    proposal({**refund, "amountMinor": 25000}, request_id=key, expected=409)
    review(first, support, expected=403)
    review(first, finance, expected=409, digest="0" * 64)
    other = snapshot(tokens["other-manager"])
    require(not other["agents"] and not other["decisions"], "Another tenant can see business records.")
    review(first, tokens["other-manager"], "deny", expected=404)
    require(not writes, "A rejected review reached the connector.")

    def concurrent_review():
        body = json.dumps({"id": first["id"], "digest": first["digest"], "decision": "approve"}).encode()
        req = urllib.request.Request(api + "/decisions", body, {"Content-Type": "application/json", **finance})
        try:
            response = _opener(use_proxy=False).open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = [executor.submit(concurrent_review) for _ in range(2)]
        require(sorted(f.result() for f in responses) == [200, 409], "Concurrent reviews did not resolve once.")
    require(first["id"] == writes[0]["id"], "Receipt does not match approved refund.")
    require([item["action"] for item in writes] == [refund], "Concurrent reviews changed or duplicated the refund.")

    reply = {"kind": "customer_reply", "afterRefundId": first["id"], "recipient": "customer-12",
             "body": "We confirmed your refund."}
    followup = proposal(reply)
    review(followup, support)
    require([item["action"] for item in writes] == [refund, reply], "Support reply failed after confirmed refund.")

    ambiguous = {**refund, "orderId": "order-uncertain"}
    interrupted = proposal(ambiguous, case="case-02")
    require(review(interrupted, finance)["status"] == "uncertain", "Lost acknowledgment must remain uncertain.")
    require(len(writes) == 3, "Unexpected writes before reconciliation.")

    waiting_reply = {**reply, "afterRefundId": interrupted["id"]}
    proposal(waiting_reply, case="case-02", expected=409)
    review(interrupted, finance, expected=409)
    report = snapshot()["report"]
    require(report["uncertain"] == 1 and report["succeeded"] == 2, "Report does not match provider outcomes.")
    reconciled = review(interrupted, finance, "confirm", note="Verified the provider receipt.")
    require(reconciled["status"] == "succeeded" and len(writes) == 3, "Reconciliation caused a write.")
    revised = proposal(waiting_reply, case="case-02")
    review(revised, support, "request_changes", note="Include the reference in the reply.")
    review(revised, support, expected=409)
    corrected = proposal({**waiting_reply, "body": "Your refund was issued. Reference TEST."}, case="case-02")
    require(corrected["id"] != revised["id"] and corrected["digest"] != revised["digest"],
            "A changed reply reused an approval.")
    review(corrected, support, "deny")

    # Seed the same revocation table used by the operator quarantine and circuit breaker.
    pending = proposal(refund, case="case-revoked")
    subprocess.run(
        [psql, env["DATABASE_ADMIN_URL"], "-X", "-v", "ON_ERROR_STOP=1", "-c",
         f"insert into monolith.revoked_sessions(tenant_id,agent_id,session_id,reason,triggered_by) "
         f"values ('{tenant}','{agent}','run','acceptance','test')"],
        env=env, check=True, capture_output=True, timeout=15,
    )
    proposal(refund, case="case-blocked", expected=403)
    require(review(pending, finance)["status"] == "revoked", "Revocation must be visible to the reviewer.")
    final = snapshot()
    expected_statuses = {first["id"]: "succeeded", followup["id"]: "succeeded", interrupted["id"]: "succeeded",
                         revised["id"]: "changes_requested", corrected["id"]: "denied", pending["id"]: "revoked"}
    require({r["id"]: r["status"] for r in final["decisions"]} == expected_statuses,
            "Inbox outcomes disagree with the recorded workflow.")
    require(final["report"]["succeeded"] == 3 and final["report"]["uncertain"] == 0 and
            final["report"]["changes_requested"] == 1 and final["report"]["denied"] == 1,
            "Final business report does not reflect the reconciled workflow.")
    require({a["decision_id"] for a in final["activity"] if a["decision_id"]} == set(expected_statuses),
            "Activity did not include each decision.")
    require(len(writes) == 3, "Revoked workload dispatched an action.")
    # Query as the deployed database role without an application-side WHERE clause.
    # A missing RLS policy would leak rows even if the dashboard's filter is correct.
    for scope, count in [(tenant, len(expected_statuses)), (tenant + "-other", 0)]:
        result = subprocess.run(
            [psql, env["DATABASE_URL"], "-XqAt", "-v", "ON_ERROR_STOP=1", "-c",
             f"set role monolith_app; set monolith.tenant_id = '{scope}'; select count(*) from monolith.business_decisions"],
            env=env, check=True, capture_output=True, text=True, timeout=15,
        )
        require(result.stdout.strip() == str(count), "Restricted database role failed tenant isolation check.")
