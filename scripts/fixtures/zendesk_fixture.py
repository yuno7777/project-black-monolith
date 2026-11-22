"""Measure the connector's exact HTTP requests against a local Zendesk API fixture."""

import io
import json
import urllib.error
from urllib.parse import parse_qs, urlsplit

TICKET = 42
REPLY = {"kind": "customer_reply", "recipient": "zendesk:pilot-sandbox:42", "body": "Synthetic reply.\nThanks!"}


class ZendeskFixture:
    def __init__(self):
        self.writes = []
        self.receipts = []
        self.fail = ""
        self.block = None

    def open(self, request, timeout):
        assert timeout == 2
        parsed = urlsplit(request.full_url)
        assert parsed.scheme == "https" and parsed.netloc == "pilot-sandbox.zendesk.com"
        assert parsed.path in ("/api/v2/tickets/42.json", "/api/v2/tickets/42/audits")
        assert request.get_header("Authorization") == "Bearer zendesk-token-for-testing"
        if request.method == "PUT":
            if self.fail == "rejected":
                raise urllib.error.HTTPError(request.full_url, 409, "Update conflict", {}, None)
            ticket = json.loads(request.data)["ticket"]
            assert ticket["safe_update"] is True and ticket["updated_stamp"] == "2026-11-22T10:00:00Z"
            self.writes.append(ticket)
            if self.block:
                started, release = self.block
                started.set()
                assert release.wait(5)
            audit = {"ticket_id": TICKET, "metadata": {"custom": ticket["metadata"]}, "events": [{
                "type": "Comment", "id": 50 + len(self.writes), **ticket["comment"],
            }]}
            if self.fail == "changed":
                audit["events"][0]["body"] = "Changed by the provider."
            self.receipts.append(audit)
            if self.fail == "lost":
                raise TimeoutError("lost response")
            response = {"audit": audit}
        elif parsed.path.endswith("/audits"):
            if parse_qs(parsed.query).get("page[after]") == ["next fixture page"]:
                response = {"audits": self.receipts, "meta": {"has_more": False}}
            else:
                response = {"audits": [], "meta": {"has_more": True, "after_cursor": "next fixture page"}}
        else:
            response = {"ticket": {"id": TICKET, "updated_at": "2026-11-22T10:00:00Z"}}
        return io.BytesIO(json.dumps(response).encode())
