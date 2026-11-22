# Business control center

A support agent receives a request to refund $125. Who can approve it, which
payment will receive it, and when can the agent tell the customer it went
through? Open **Business workspace** at `/business` to practice the routing, review the
two proposed actions, and look up the outcome after the shift changes.

## Set up a team

1. Start a customer-hosted dashboard and its PostgreSQL database with the
   migrations from this checkout. Sign in with a tenant-scoped operator
   account. Use an admin for setup, an analyst for routine review, and a viewer
   for read access. [Stack setup](../README.md#try-it) · [Operator sign-in](IDENTITY_AND_ACCESS.md#operator-configuration-and-browser-sessions)
2. Give the workload its own grant in `MONOLITH_WORKLOAD_GRANTS_JSON`. Use the
   same agent ID in the grant and the directory. The dashboard binds incoming
   workload requests to `MONOLITH_TENANT_ID`. Give each workload-serving
   deployment its tenant configuration and give the raw workload token only to
   that workload. [Workload credentials](IDENTITY_AND_ACCESS.md#authenticated-agent-workloads)
3. Configure `MONOLITH_BUSINESS_REVIEWERS_JSON` on the dashboard. The example
   below assigns one operator per review team. Replace the example tenant and
   actor names with the exact identities used at sign-in. Set
   `MONOLITH_TENANT_ID=tenant-a` for this example. The stock Compose
   configuration creates one operator. To sign in as separate reviewers,
   supply the dashboard's `OPERATOR_TOKENS_JSON` via a Compose override or
   configure your identity provider as described in the identity guide. For
   Compose, save this fragment as `compose.override.yaml`.

   ```yaml
   services:
     dashboard:
       environment:
         OPERATOR_TOKENS_JSON: ${BUSINESS_OPERATOR_ACCOUNTS_JSON:?set the operator account map}
   ```

   Set `BUSINESS_OPERATOR_ACCOUNTS_JSON` through your deployment secret store
   using the following structure. Supply a distinct random token for each
   account. Use `docker compose -f docker-compose.yml -f compose.override.yaml
   up -d --build --wait` to apply both files. For native deployment, supply
   the same JSON directly as `OPERATOR_TOKENS_JSON`.

   ```json
   {
     "manager":{"tenant_id":"tenant-a","role":"admin","token":"REPLACE_WITH_MANAGER_SECRET"},
     "alice":{"tenant_id":"tenant-a","role":"analyst","token":"REPLACE_WITH_SUPPORT_SECRET"},
     "sam":{"tenant_id":"tenant-a","role":"analyst","token":"REPLACE_WITH_FINANCE_SECRET"}
   }
   ```

   Assign review teams to the two analysts in `MONOLITH_BUSINESS_REVIEWERS_JSON`.

   ```json
   [
     {"tenant":"tenant-a","actor":"alice","teams":["support"]},
     {"tenant":"tenant-a","actor":"sam","teams":["finance"]}
   ]
   ```

4. In **Agents**, register the workload as `support-agent`, give it an owner,
   and select **Issue refund** and **Send customer reply**.
   In **Policies & practice**, choose
   USD, a $100 refund threshold, the `support` team for ordinary review, and
   the `finance` team for refunds over the threshold. Saving these settings
   requires an admin. Approval also requires membership in the assigned team.
5. To execute approved actions, configure a customer-operated connector for
   the tenant. Provide it through the dashboard's secret configuration and
   restart the dashboard after changing its environment. For a rehearsal, use
   a connector that records test actions and returns synthetic receipts.

   ```json
   [{"tenant":"tenant-a","url":"https://connector.example.com/monolith","token":"REPLACE_WITH_CONNECTOR_SECRET"}]
   ```

   Store that JSON in `MONOLITH_BUSINESS_CONNECTORS_JSON`. The host is an
   example. Issue a dedicated secret shared by the dashboard and your
   connector. Keep provider credentials in the connector.

## Choose a workflow

| Workflow | Reviewed action | Review team under the default policy |
| --- | --- | --- |
| Customer support (`support`) | Send an exact message to a named recipient | Support |
| Sales follow-up (`sales`) | Change one named field on a CRM record or send one customer message | Support |
| Invoice review (`invoice`) | Record a review note for a named invoice | Finance |
| Customer refund (`refund`) | Refund a specified order and destination, then propose a separate follow-up message | Support or finance for the refund, support for the message |

Give each case a stable ID in the source business system. For example, use the
same support ticket ID when the customer asks twice about one refund. The
connector is responsible for enforcing the remaining refundable amount even
when two different tickets concern the same order.

## Rehearse the policy

Open **Policies & practice**. Choose the refund workflow and preview a $100
refund, then a $125 refund with the same currency and destination. At a $100
threshold, the first belongs to support and the second to finance. Both
require explicit approval. Practice is a preview. It can be used before
connecting a payment or messaging system. A newly registered agent starts in
practice-only mode. Its workload can submit a practice request using its grant
and a body containing `templateId` and `action`. After practicing, an admin
can switch the agent out of practice-only mode in **Agents** to admit proposals.

### Try the local connector

With the native dashboard running on the same host, set
`MONOLITH_PRACTICE_CONNECTOR_TOKEN` to a dedicated random secret. Run the
provided payment and messaging stand-in in a separate terminal. Choose a
database path in a private directory.

```sh
python3 scripts/business_practice_connector.py serve --tenant tenant-a --db ./practice.sqlite3
```

Use `http://127.0.0.1:4177/monolith` and that shared secret in the tenant's
dashboard connector configuration. The receiver records synthetic receipts in
SQLite. For a dashboard inside a container, its loopback address points into
the container. Use a connector reachable over HTTPS for that deployment.

## Submit the refund and customer reply

In this example the configured workload represents `support-agent` in
`tenant-a`. Set `MONOLITH_DASHBOARD_API_URL` to the dashboard origin and
provide its issued workload token as `MONOLITH_WORKLOAD_TOKEN`. Use test
order and destination identifiers that your connector understands.

```sh
refund_request=$(python3 -c 'import uuid; print(uuid.uuid4())')
curl --fail-with-body -sS "$MONOLITH_DASHBOARD_API_URL/api/business/proposals" \
  -H "X-Monolith-Workload-Token: $MONOLITH_WORKLOAD_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<EOF_JSON
{
  "requestId": "$refund_request",
  "caseId": "case-51",
  "templateId": "refund",
  "action": {
    "kind": "refund", "orderId": "order-51", "destination": "original-payment-51",
    "amountMinor": 12500, "currency": "USD"
  }
}
EOF_JSON
```

Keep the returned `decision.id`. For a retry use the same request ID and
payload. `amountMinor` is an integer in minor units. For USD, 12500 represents
$125.00. The order and destination identify what finance is authorizing.

1. As Sam on the finance team, open the **Decision inbox** and find
   `case-51`. Check the order, destination, amount and currency. Select
   **Approve and send**, then **Confirm decision**. Check the resulting
   provider confirmation reference. If the proposal is incorrect, select
   **Request changes** and explain the correction. A revised proposal requires
   a fresh review. Pending proposals expire after 15 minutes.
2. Once the refund has succeeded, submit a separate follow-up from the same
   agent in the same case. Replace the placeholder with the refund decision ID
   and keep the new request ID for retries. The message below uses a literal
   dollar sign.

   ```sh
   refund_id='REPLACE_WITH_CONFIRMED_REFUND_DECISION_ID'
   reply_request=$(python3 -c 'import uuid; print(uuid.uuid4())')
   python3 -c '
   import json, sys
   print(json.dumps({
       "requestId": sys.argv[1], "caseId": "case-51", "templateId": "refund",
       "action": {"kind": "customer_reply", "recipient": "customer-51",
                  "body": "Your $125.00 refund was issued.", "afterRefundId": sys.argv[2]}
   }))' "$reply_request" "$refund_id" |
     curl --fail-with-body -sS "$MONOLITH_DASHBOARD_API_URL/api/business/proposals" \
       -H "X-Monolith-Workload-Token: $MONOLITH_WORKLOAD_TOKEN" \
       -H 'Content-Type: application/json' --data-binary @-
   ```

3. As Alice on the support team, check the displayed recipient, message and
   refund ID. Approve and confirm the message. Look up both receipts in the
   connected system. A refund and a message are separate business effects.

## Review the shift

In **Activity & reports**, open **Awaiting review** to find pending work,
**Past deadline** to see missed approvals, and **Uncertain outcome** for
sends awaiting provider reconciliation. The report also counts denials,
change requests and confirmed actions and shows average review time. Each
activity entry records an actor and a timestamp. Use **View decision** on an
entry to inspect its case, exact proposal, reviewer and available receipt.
Use **All decisions** and search for `case-51` to follow both the refund and
customer message. The example contributes two confirmed actions when the connector
has acknowledged both.

## Implement the customer connector

The dashboard sends an authenticated HTTP POST with `Authorization: Bearer`
and an `Idempotency-Key` equal to the decision ID. The JSON body contains
`id`, `tenant` and the approved `action`. Use HTTPS for a remote connector.
HTTP on loopback is supported for a local rehearsal.

Validate the credential and tenant. Resolve identifiers such as `order-51`
against that tenant's data. Check the order, refundable amount and original
payment destination at the provider. Use the decision ID as the provider's
idempotency key where supported and persist the result so a repeated delivery
can return the original receipt. The dashboard expects a receipt within four
seconds.

Return HTTP 200 with a JSON receipt for a confirmed effect. The response ID
must match the request ID in the connector body.

```json
{"id":"DECISION_UUID","status":"succeeded","reference":"refund-provider-reference"}
```

Return `"status":"failed"` with a reference only when the provider definitively
rejected the operation with zero writes. A timeout, malformed receipt, or
ambiguous provider result requires reconciliation. If an acknowledgment is
missing, look up the provider's receipt by decision ID, order, and destination. Record the supporting reference
when using **Confirm applied** or **Confirm not applied** in the decision
inbox. The connector implements the integration with your payment,
messaging, sales or invoice system. The workflow templates define the actions
that Black Monolith can review.

## Recover after a database restore

Keep the dashboard stopped and its connector credential disabled while
restoring PostgreSQL. A refund or reply may have reached the provider after
the backup was taken. As the maintenance administrator, expire restored
pending approvals and flag interrupted sends for investigation. The following
statement records each change in the same transaction.

```sql
WITH recovered AS (
  UPDATE monolith.business_decisions
  SET status = CASE status WHEN 'pending' THEN 'expired' ELSE 'uncertain' END
  WHERE status IN ('pending', 'dispatching')
  RETURNING tenant_id, id, status
)
INSERT INTO monolith.business_activity (tenant_id, decision_id, actor, event, note)
SELECT tenant_id, id, 'recovery', status, 'Database restored from backup'
FROM recovered;
```

Start the dashboard without the connector credential. Compare each affected
case with the provider's ledger, including provider operations after the backup
cutoff that have no corresponding restored decision. Record the evidence and
resolve outstanding differences before enabling the connector or asking for a
new proposal. To look up a receipt on the local practice connector, use the decision ID.

```sh
python3 scripts/business_practice_connector.py receipt --db ./practice.sqlite3 --tenant tenant-a --id DECISION_UUID
```

## API access

| Operation | Endpoint | Credential |
| --- | --- | --- |
| Read agents, policy, decisions, activity and report | `GET /api/business` | Viewer or above |
| Preview a policy result | `POST /api/business/practice` | Viewer or above, or workload grant for an agent practice request |
| Save agent or policy | `POST /api/business/agents`, `POST /api/business/policies` | Admin |
| Submit an exact action | `POST /api/business/proposals` | Workload grant |
| Decide or reconcile | `POST /api/business/decisions` | Analyst or admin on the required team |

Operator API clients use a tenant-scoped operator bearer token or an
authenticated browser session. Direct reviews include the decision ID, the
digest of the displayed action, and the reviewer's decision. Keep that digest
bound to what the reviewer actually saw.

## Local verification

Run the dashboard suite and Linux native smoke checks from a clean checkout
with no existing `.env`. The native checks require the locked module
dependencies and PostgreSQL 17 binaries. The runner starts a disposable
database, the production dashboard and loopback service fixtures.

```sh
npm ci --prefix dashboard
npm --prefix dashboard test
npm --prefix dashboard run lint
npm --prefix dashboard run build
cargo build --locked --manifest-path mcp-shield/Cargo.toml
PG_BIN=/path/to/postgresql/17/bin python3 scripts/native_smoke.py
```

The local acceptance run used a $125 synthetic refund with a $100 threshold.
Practice and denied operations sent zero requests. A support reviewer could not
approve the refund, and a finance reviewer approved it once across competing
requests. A separate support approval sent the customer reply. A second refund
lost its acknowledgment, which blocked the dependent reply until a reviewer
recorded verification. Reconciliation sent zero additional requests. Replay,
changed payloads, a revoked session, and cross-tenant access were also checked.
The native suite ran the existing GitHub issue triage checks against a loopback
GitHub fixture.

A separate Chromium run covered browser sign-in, promotion from practice mode,
policy preview, the finance and support approvals, viewer permissions, and
the report drilldown. Both runs used synthetic business data.
