import io
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
from http.client import HTTPConnection
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from business_practice_connector import PracticeServer, main


class PracticeConnectorTests(unittest.TestCase):
    def setUp(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.db = Path(tempdir.name) / "practice receipts.sqlite3"
        self.token = "local-practice-token-fixture"
        self.decision_id = str(uuid.uuid4())
        self.envelope = {"id": self.decision_id, "tenant": "pilot", "action": {
            "kind": "customer_reply", "recipient": "customer-1", "body": " Hello, customer.\n",
        }}
        self.headers = {"Content-Type": "application/json", "Authorization": "Bearer " + self.token,
                        "Idempotency-Key": self.decision_id}

    def start(self):
        server = PracticeServer(0, self.db, "pilot", self.token)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.03})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        return server

    def post(self, server, data, headers=None, path="/monolith"):
        with closing(HTTPConnection(*server.server_address, timeout=5)) as client:
            client.request("POST", path, body=json.dumps(data), headers=headers or self.headers)
            response = client.getresponse()
            return response.status, json.loads(response.read())

    def test_concurrent_replay_restart_and_receipt_lookup(self):
        server = self.start()
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: self.post(server, self.envelope), range(8)))
        expected = {"id": self.decision_id, "status": "succeeded", "reference": f"practice-{self.decision_id}"}
        self.assertEqual(responses, [(200, expected)] * 8)
        server.shutdown()
        reopened = self.start()
        self.assertEqual(self.post(reopened, self.envelope), (200, expected))
        changed = {**self.envelope, "action": {**self.envelope["action"], "body": "edited"}}
        self.assertEqual(self.post(reopened, changed)[0], 409)
        with closing(sqlite3.connect(self.db)) as db:
            actions = db.execute("select action from practice_decisions").fetchall()
        self.assertEqual([json.loads(row[0]) for row in actions], [self.envelope["action"]])
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["receipt", "--db", str(self.db), "--tenant", "pilot", "--id", self.decision_id]), 0)
        self.assertEqual(json.loads(output.getvalue()), expected)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["receipt", "--db", str(self.db), "--tenant", "other", "--id", self.decision_id]), 1)

    def test_rejected_requests_leave_ledger_empty(self):
        server = self.start()
        for expected, data, headers in [
            (401, self.envelope, {"Authorization": "Bearer wrong"}),
            (403, {**self.envelope, "tenant": "other"}, {}),
            (422, {**self.envelope, "id": str(uuid.uuid4())}, {}),
            (422, self.envelope, {"Idempotency-Key": "x"}),
            (422, {**self.envelope, "action": {"kind": "other"}}, {}),
            (422, {**self.envelope, "action": {**self.envelope["action"], "cc": "other"}}, {}),
            (415, self.envelope, {"Content-Type": "text/plain"}),
        ]:
            with self.subTest(expected=expected):
                self.assertEqual(self.post(server, data, {**self.headers, **headers})[0], expected)
        # Send only the oversized declaration. The server can reject it before
        # reading a body, and closing with unread bytes can reset a macOS socket.
        with closing(HTTPConnection(*server.server_address, timeout=5)) as client:
            client.request("POST", "/monolith", headers={**self.headers, "Content-Length": "82000"})
            self.assertEqual(client.getresponse().status, 413)
        self.assertEqual(self.post(server, self.envelope, path="/other")[0], 404)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("select count(*) from practice_decisions").fetchone()[0], 0)
