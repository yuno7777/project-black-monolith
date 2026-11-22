# Zendesk support pilot

Connect the customer-hosted Monolith dashboard to a Zendesk sandbox using the
bundled loopback connector. The first workflow sends an approved public reply
to one of the synthetic tickets you allowlist. An existing support agent needs
only its Monolith workload grant. The connector holds the Zendesk OAuth token.

## Configure the pilot

1. Create synthetic tickets in a Zendesk sandbox and verify that their
   requesters and notifications use test addresses. Note the sandbox subdomain
   and the ticket IDs. Create an agent OAuth access token with permission to
   read and update those tickets and read their audits.
2. In a separate terminal or service, set `MONOLITH_ZENDESK_ACCESS_TOKEN` through
   your secret store. Set `MONOLITH_ZENDESK_CONNECTOR_TOKEN` to a dedicated
   random bearer token. Keep the SQLite file in a private directory with
   persistent storage. This file tracks decisions even if the connector
   restarts.

   ```sh
   mkdir -m 700 ./zendesk-pilot-state
   python3 scripts/business_zendesk_connector.py \
     --db ./zendesk-pilot-state/receipts.sqlite3 \
     --tenant tenant-a --sandbox-subdomain your-sandbox --ticket 42 --ticket 43 \
     serve --port 4178
   ```

3. In the dashboard's `MONOLITH_BUSINESS_CONNECTORS_JSON`, configure the same
   tenant, local endpoint and the **connector** bearer token. Restart the
   dashboard after changing its environment. The connector listens on
   loopback. Run it on the same host as the native dashboard, or connect to
   it through an HTTPS service accessible to the dashboard container.

   ```json
   [{"tenant":"tenant-a","url":"http://127.0.0.1:4178/monolith","token":"REPLACE_WITH_CONNECTOR_BEARER_TOKEN"}]
   ```

4. Register the support agent with the **Send customer reply** permission.
   Assign a reviewer to the default support team and use practice mode first.
   The business setup guide covers workload credentials and reviewer roles.
   [Business control center](BUSINESS_CONTROL_CENTER.md#set-up-a-team)

## Rehearse a support reply

Submit a proposal with workflow `support`, a fresh `requestId`, and a
`caseId` that identifies the synthetic ticket. For example, use
`caseId: "sandbox-ticket-42"` and this exact action:

```json
{"kind":"customer_reply","recipient":"zendesk:your-sandbox:42","body":"Thanks for the report. Which app version are you using?"}
```

Use plain text with single spaces and single line breaks. Zendesk can expand
placeholders or rewrite HTML and whitespace. The connector refuses known
transformations before dispatch and checks the returned audit against the
approved text.

- Approve one draft in the **Decision inbox**. Verify that the confirmed
  provider reference points to the exact public reply on the chosen ticket.
  Attempting to approve it again must leave the ticket unchanged.
- Deny a second draft. Verify that it creates no comment or send receipt.
- Exercise a lost acknowledgment in the local test. In a live sandbox, if
  a decision becomes uncertain, use the reconciliation procedure below.
  A replay of an uncertain decision must leave the ticket unchanged.

Use the two-phase acceptance runner to save the decision IDs, final dashboard
statuses and Zendesk receipt. Configure a separate Zendesk verifier OAuth
token with read access to the sandbox ticket audits as
`MONOLITH_VERIFY_ZENDESK_TOKEN`. Set `MONOLITH_DASHBOARD_API_URL` to your
dashboard, `MONOLITH_WORKLOAD_TOKEN` for preparation and
`MONOLITH_OPERATOR_TOKEN` for the evidence check.

```sh
python3 scripts/verify_zendesk_pilot.py prepare \
  --sandbox-subdomain your-sandbox --ticket 42 --state ./zendesk-pilot-state/run.json
```

Approve the printed **approved** decision and deny the printed **denied**
decision in the dashboard. Then check the recorded outcome against Zendesk.

```sh
python3 scripts/verify_zendesk_pilot.py check \
  --sandbox-subdomain your-sandbox --ticket 42 --state ./zendesk-pilot-state/run.json \
  --evidence ./zendesk-pilot-state/evidence.json
```

The check reads both systems and only saves evidence after it finds one exact
approved reply and zero denied replies. Use new state and evidence paths for
each run. The evidence contains decision IDs, digests, outcomes and the
provider reference. Preserve the connector ledger with your backups.
After restoring a backup, compare its decisions with provider records before
re-enabling the connector. [Recovery procedure](BUSINESS_CONTROL_CENTER.md#recover-after-a-database-restore)

## Reconcile a lost acknowledgment

The connector stores a dispatch claim before contacting Zendesk, so an
interrupted request cannot cause a second send for the same decision ID.
Zendesk records the Monolith decision ID and exact action digest as audit
metadata when it accepts a reply. The following command checks the ticket's
audit history for one matching public comment. It performs read-only provider
requests and updates the local receipt if it finds a match.

```sh
python3 scripts/business_zendesk_connector.py \
  --db ./zendesk-pilot-state/receipts.sqlite3 \
  --tenant tenant-a --sandbox-subdomain your-sandbox --ticket 42 --ticket 43 \
  reconcile --id DECISION_UUID
```

If the command finds a matching comment, use **Confirm applied** on the
decision and enter the provider reference. Leave the outcome uncertain if
the connector cannot find a unique match. Check the details in Zendesk before
making a manual decision or starting a new proposal for the same ticket.

## Local verification

```sh
python3 -m unittest discover -s scripts/tests -p 'test_business*.py'
PG_BIN=/path/to/postgresql/17/bin python3 scripts/native_smoke.py
```

The native test verifies the production dashboard, PostgreSQL, connector
HTTP endpoint, durable dispatch ledger, and a Zendesk API fixture. It covers
approved, denied, replayed, and reconciled decisions with synthetic replies.
Live Zendesk and GitHub verification require their designated test environments.

[Zendesk ticket comments](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/)
· [Zendesk ticket audits](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_audits/)
· [Zendesk audit metadata](https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets/#setting-metadata)
