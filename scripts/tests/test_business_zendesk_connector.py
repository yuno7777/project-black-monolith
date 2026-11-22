import concurrent.futures
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from business_practice_connector import RequestError
from business_zendesk_connector import DispatchLedger, Zendesk, reply_digest
from fixtures.zendesk_fixture import REPLY, TICKET, ZendeskFixture


class ZendeskConnectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db = Path(temporary.name) / "zendesk-receipts.sqlite3"
        self.fixture = ZendeskFixture()
        self.zendesk = Zendesk("pilot-sandbox", "zendesk-token-for-testing", {TICKET})
        self.zendesk.opener = self.fixture
        self.ledger = DispatchLedger(self.db, "support-tenant", self.zendesk)
        self.decision = str(uuid4())

    def assert_refused(self, status, operation, *args):
        with self.assertRaises(RequestError) as caught:
            operation(*args)
        self.assertEqual(caught.exception.status, status)

    def test_exact_reply_and_persistent_replay(self):
        first = self.ledger.dispatch(self.decision, REPLY)
        self.assertEqual(first, {"id": self.decision, "status": "succeeded", "reference": "zendesk-ticket-42-comment-51"})
        sent, = self.fixture.writes
        self.assertEqual(sent["comment"], {"public": True, "body": REPLY["body"]})
        self.assertEqual(sent["metadata"], {"monolith_decision_id": self.decision,
                                            "monolith_action_sha256": reply_digest(REPLY)})
        reopened = DispatchLedger(self.db, "support-tenant", self.zendesk)
        self.assertEqual(reopened.dispatch(self.decision, REPLY), first)
        self.assert_refused(409, reopened.dispatch, self.decision, {**REPLY, "body": "Changed draft"})
        self.assertEqual(len(self.fixture.writes), 1)
        if os.name != "nt":
            self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_cross_ticket_and_domain_dispatches_are_refused(self):
        for recipient in ["zendesk:another-sandbox:42", "zendesk:pilot-sandbox:43", "https://other.example"]:
            with self.subTest(recipient=recipient):
                self.assert_refused(403, self.ledger.dispatch, self.decision, {**REPLY, "recipient": recipient})
        self.assert_refused(422, self.ledger.dispatch, self.decision, {**REPLY, "afterRefundId": str(uuid4())})
        self.assertFalse(self.fixture.writes)

    def test_provider_normalization_and_placeholders_are_refused_before_send(self):
        for body in ("Hello {{ticket.requester.email}}", "<b>Hello</b>", "Two  spaces", "Leading\n\nline", "trailing "):
            self.assert_refused(422, self.ledger.dispatch, self.decision, {**REPLY, "body": body})
        self.assertFalse(self.fixture.writes)

    def test_concurrent_replay_is_refused_while_sending(self):
        started, release = self.fixture.block = threading.Event(), threading.Event()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            first = pool.submit(self.ledger.dispatch, self.decision, REPLY)
            try:
                self.assertTrue(started.wait(5))
                self.assert_refused(503, self.ledger.dispatch, self.decision, REPLY)
            finally:
                release.set()
            self.assertEqual(first.result()["status"], "succeeded")
        self.assertEqual(len(self.fixture.writes), 1)

    def test_lost_acknowledgment_reconciles_across_restart_and_pagination(self):
        self.fixture.fail = "lost"
        self.assert_refused(503, self.ledger.dispatch, self.decision, REPLY)
        reopened = DispatchLedger(self.db, "support-tenant", self.zendesk)
        self.assert_refused(503, reopened.dispatch, self.decision, REPLY)
        other_tenant = DispatchLedger(self.db, "another-tenant", self.zendesk)
        self.assert_refused(404, other_tenant.reconcile, self.decision)
        receipt = reopened.reconcile(self.decision)
        self.assertEqual(receipt["reference"], "zendesk-ticket-42-comment-51")
        self.assertEqual(reopened.dispatch(self.decision, REPLY), receipt)
        self.assertEqual(len(self.fixture.writes), 1)

    def test_update_collision_records_definitive_failure(self):
        self.fixture.fail = "rejected"
        result = self.ledger.dispatch(self.decision, REPLY)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reference"], "zendesk-http-409")
        self.assertEqual(self.ledger.dispatch(self.decision, REPLY), result)
        self.assertFalse(self.fixture.writes)

    def test_changed_body_or_multiple_provider_receipts_stay_uncertain(self):
        self.fixture.fail = "changed"
        self.assert_refused(503, self.ledger.dispatch, self.decision, REPLY)
        self.assertIsNone(self.ledger.reconcile(self.decision))
        event = {**self.fixture.receipts[0]["events"][0], "body": REPLY["body"]}
        self.fixture.receipts[0]["events"] = [event]
        self.fixture.receipts.append({**self.fixture.receipts[0], "events": [{**event, "id": 52}]})
        self.assertIsNone(self.ledger.reconcile(self.decision))
        self.fixture.receipts[1]["events"][0]["body"] = "Different body on duplicate receipt."
        self.assertIsNone(self.ledger.reconcile(self.decision))
        self.assertEqual(len(self.fixture.writes), 1)
