"""Dispatch approved replies to an allowlisted Zendesk sandbox and reconcile receipts."""

import argparse
import hashlib
import http.client
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path

from business_practice_connector import TENANT, TOKEN, ConnectorServer, RequestError, canonical_uuid

SUBDOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
RECIPIENT = re.compile(r"zendesk:(?P<subdomain>[a-z0-9-]{1,63}):(?P<ticket>[1-9][0-9]{0,17})")
REJECTED = {400, 401, 403, 404, 409, 422, 429}
MAX_RESPONSE = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Zendesk:
    def __init__(self, subdomain: str, access_token: str, tickets: set[int]):
        if not SUBDOMAIN.fullmatch(subdomain) or not TOKEN.fullmatch(access_token) or not tickets:
            raise ValueError("Configure a Zendesk subdomain, an OAuth access token and a ticket allowlist.")
        self.subdomain = subdomain
        self.origin = f"https://{subdomain}.zendesk.com"
        self.access_token = access_token
        self.tickets = tickets
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path: str, payload=None) -> dict:
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.access_token}"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.origin + path, headers=headers, data=data,
                                         method="GET" if data is None else "PUT")
        try:
            with self.opener.open(request, timeout=2) as response:
                body = response.read(MAX_RESPONSE + 1)
            if len(body) <= MAX_RESPONSE:
                content = json.loads(body)
                if isinstance(content, dict):
                    return content
        except urllib.error.HTTPError:
            raise
        except (OSError, ValueError, RecursionError, http.client.HTTPException) as error:
            raise RequestError(503, "Zendesk outcome could not be verified.") from error
        raise RequestError(503, "Zendesk returned an invalid receipt.")

    def ticket_for(self, action: dict) -> int:
        if (action.get("kind") != "customer_reply" or set(action) != {"kind", "recipient", "body"}):
            raise RequestError(422, "This connector accepts only standalone customer replies.")
        match = RECIPIENT.fullmatch(action["recipient"])
        if not match or match["subdomain"] != self.subdomain or int(match["ticket"]) not in self.tickets:
            raise RequestError(403, "Reply target is outside the configured Zendesk ticket allowlist.")
        return int(match["ticket"])

    def send(self, ticket_id: int, decision_id: str, action: dict, digest: str) -> str:
        path = f"/api/v2/tickets/{ticket_id}.json"
        ticket = self.request(path).get("ticket")
        if (not isinstance(ticket, dict) or ticket.get("id") != ticket_id
                or not isinstance(ticket.get("updated_at"), str) or not ticket["updated_at"]):
            raise RequestError(503, "Zendesk did not return the expected ticket revision.")
        result = self.request(path, {"ticket": {
            "safe_update": True,
            "updated_stamp": ticket["updated_at"],
            "comment": {"body": action["body"], "public": True},
            "metadata": {"monolith_decision_id": decision_id, "monolith_action_sha256": digest},
        }})
        reference = audit_reference(result.get("audit"), ticket_id, action["recipient"], decision_id, digest)
        if not reference:
            raise RequestError(503, "Zendesk did not confirm the approved reply.")
        return reference

    def audits(self, ticket_id: int):
        if ticket_id not in self.tickets:
            raise RequestError(403, "Ticket is outside the configured Zendesk allowlist.")
        query = {"page[size]": "100"}
        for _ in range(10):
            data = self.request(f"/api/v2/tickets/{ticket_id}/audits?" + urllib.parse.urlencode(query))
            audits = data.get("audits")
            if not isinstance(audits, list):
                raise RequestError(503, "Zendesk did not return ticket audits.")
            yield from audits
            meta = data.get("meta", {})
            if not isinstance(meta, dict):
                raise RequestError(503, "Zendesk audit pagination was invalid.")
            if meta.get("has_more") is False or (
                    "has_more" not in meta and "next_page" in data and data["next_page"] is None):
                return
            cursor = meta.get("after_cursor")
            if not isinstance(cursor, str) or not cursor or len(cursor) > 4096 or cursor == query.get("page[after]"):
                break
            query["page[after]"] = cursor
        raise RequestError(503, "Zendesk audit history could not be checked to completion.")

    def find(self, ticket_id: int, recipient: str, decision_id: str, digest: str) -> str | None:
        references = [audit_reference(audit, ticket_id, recipient, decision_id, digest)
                      for audit in self.audits(ticket_id) if matches_decision(audit, ticket_id, decision_id, digest)]
        return references[0] if len(references) == 1 else None


def reply_digest(action: dict) -> str:
    encoded = json.dumps(action, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def matches_decision(audit, ticket_id: int, decision_id: str, digest: str) -> bool:
    if not isinstance(audit, dict) or audit.get("ticket_id") != ticket_id:
        return False
    metadata = audit.get("metadata")
    custom = metadata.get("custom") if isinstance(metadata, dict) else None
    return (isinstance(custom, dict) and custom.get("monolith_decision_id") == decision_id
            and custom.get("monolith_action_sha256") == digest)


def audit_reference(audit, ticket_id: int, recipient: str, decision_id: str, digest: str) -> str | None:
    if not matches_decision(audit, ticket_id, decision_id, digest):
        return None
    events = audit.get("events")
    if not isinstance(events, list):
        return None
    comments = [event for event in events if isinstance(event, dict) and event.get("type") == "Comment"]
    if len(comments) != 1:
        return None
    comment = comments[0]
    comment_id = comment.get("id")
    body = comment.get("body")
    if type(comment_id) is not int or comment_id <= 0 or comment.get("public") is not True or not isinstance(body, str):
        return None
    observed = {"kind": "customer_reply", "recipient": recipient, "body": body}
    return f"zendesk-ticket-{ticket_id}-comment-{comment_id}" if reply_digest(observed) == digest else None


class DispatchLedger:
    def __init__(self, path: Path, tenant: str, zendesk: Zendesk):
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.path, self.tenant, self.zendesk = path, tenant, zendesk
        with closing(sqlite3.connect(path)) as db:
            db.execute("""create table if not exists zendesk_dispatch (
                tenant text not null, id text not null, recipient text not null, digest text not null,
                status text not null, reference text, primary key (tenant,id)
            )""")

    def dispatch(self, decision_id: str, action: dict) -> dict:
        ticket = self.zendesk.ticket_for(action)
        body = action["body"]
        # Zendesk can expand placeholders or rewrite whitespace and HTML.
        if (body != body.strip() or "<" in body or "{{" in body or "  " in body
                or re.search(r"\n\s*\n|[\x00-\x09\x0b-\x1f\x7f]", body)):
            raise RequestError(422, "Use plain text without placeholders, HTML, repeated spaces or blank lines.")
        digest = reply_digest(action)
        with closing(sqlite3.connect(self.path)) as db, db:
            created = db.execute("""insert into zendesk_dispatch (tenant,id,recipient,digest,status)
                values (?,?,?,?,'dispatching') on conflict (tenant,id) do nothing""",
                (self.tenant, decision_id, action["recipient"], digest)).rowcount
            if not created:
                prior = db.execute("select digest,status,reference from zendesk_dispatch where tenant=? and id=?",
                                   (self.tenant, decision_id)).fetchone()
                if prior[0] != digest:
                    raise RequestError(409, "Decision ID already belongs to a different reply.")
                if prior[2]:
                    return {"id": decision_id, "status": prior[1], "reference": prior[2]}
                raise RequestError(503, "Decision is already claimed. Reconcile its provider receipt.")
        try:
            reference = self.zendesk.send(ticket, decision_id, action, digest)
            status = "succeeded"
        except urllib.error.HTTPError as error:
            if error.code not in REJECTED:
                raise RequestError(503, "Zendesk outcome could not be verified.") from error
            status, reference = "failed", f"zendesk-http-{error.code}"
        return self.finish(decision_id, status, reference)

    def finish(self, decision_id: str, status: str, reference: str) -> dict:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""update zendesk_dispatch set status=?,reference=?
                where tenant=? and id=? and status='dispatching'""", (status, reference, self.tenant, decision_id))
            resolved = db.execute("select status,reference from zendesk_dispatch where tenant=? and id=?",
                                  (self.tenant, decision_id)).fetchone()
        return {"id": decision_id, "status": resolved[0], "reference": resolved[1]}

    def reconcile(self, decision_id: str) -> dict | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("select recipient,digest,status,reference from zendesk_dispatch where tenant=? and id=?",
                             (self.tenant, decision_id)).fetchone()
        if not row:
            raise RequestError(404, "Unknown local decision.")
        target, digest, status, reference = row
        if reference:
            return {"id": decision_id, "status": status, "reference": reference}
        ticket = self.zendesk.ticket_for({"kind": "customer_reply", "recipient": target, "body": ""})
        reference = self.zendesk.find(ticket, target, decision_id, digest)
        return self.finish(decision_id, "succeeded", reference) if reference else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--sandbox-subdomain", required=True)
    parser.add_argument("--ticket", required=True, action="append", type=int, help="Allow one synthetic ticket ID")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("serve").add_argument("--port", type=int, default=4178)
    subcommands.add_parser("reconcile").add_argument("--id", required=True)
    args = parser.parse_args(argv)
    try:
        if not TENANT.fullmatch(args.tenant) or any(not 1 <= ticket < 10**18 for ticket in args.ticket):
            parser.error("A valid tenant and positive ticket IDs are required.")
        zendesk = Zendesk(args.sandbox_subdomain, os.environ.get("MONOLITH_ZENDESK_ACCESS_TOKEN", ""), set(args.ticket))
        ledger = DispatchLedger(args.db, args.tenant, zendesk)
        if args.command == "reconcile":
            if not canonical_uuid(args.id):
                parser.error("Expected a decision UUID.")
            receipt = ledger.reconcile(args.id)
            if receipt is None:
                print("No unique provider receipt found. Leave this outcome uncertain.", file=sys.stderr)
                return 1
            print(json.dumps(receipt))
            return 0
        if not 1 <= args.port <= 65535:
            parser.error("Port must be between 1 and 65535.")
        token = os.environ.get("MONOLITH_ZENDESK_CONNECTOR_TOKEN", "")
        with ConnectorServer(args.port, args.tenant, token, ledger.dispatch) as server:
            print(f"Zendesk connector listening at http://127.0.0.1:{args.port}/monolith", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, sqlite3.Error, RequestError):
        print("Zendesk connector could not complete the command. Check configuration and the receipt ledger.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
