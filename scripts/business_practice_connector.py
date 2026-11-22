"""Rehearse approved business decisions on loopback using a durable, synthetic receipt ledger."""

import argparse
import hmac
import json
import os
import re
import sqlite3
import sys
import uuid
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 80 * 1024
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{16,512}")
TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
ACTION_FIELDS = {
    "refund": {"kind", "orderId", "destination", "amountMinor", "currency"},
    "customer_reply": {"kind", "recipient", "body"},
    "crm_update": {"kind", "recordId", "field", "value"},
    "invoice_review": {"kind", "invoiceId", "note"},
}


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def canonical_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def unique_fields(pairs: list) -> dict:
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("duplicate JSON field")
        fields[key] = value
    return fields


def validated_action(action: object) -> dict:
    if not isinstance(action, dict):
        raise RequestError(422, "Expected an action.")
    kind = action.get("kind")
    if not isinstance(kind, str) or kind not in ACTION_FIELDS:
        raise RequestError(422, "Unknown rehearsal action.")
    expected = ACTION_FIELDS[kind]
    if kind == "customer_reply" and "afterRefundId" in action:
        expected = expected | {"afterRefundId"}
        if not canonical_uuid(action["afterRefundId"]):
            raise RequestError(422, "Invalid refund decision ID.")
    if set(action) != expected:
        raise RequestError(422, "Unexpected or missing action fields.")
    for field in expected - {"amountMinor"}:
        value = action[field]
        if not isinstance(value, str) or not value.strip() or "\0" in value:
            raise RequestError(422, "Invalid action text.")
    if kind == "refund":
        amount = action["amountMinor"]
        if (type(amount) is not int or not 1 <= amount <= 2**53 - 1
                or action["currency"] not in {"USD", "EUR", "GBP", "CAD", "AUD", "JPY"}):
            raise RequestError(422, "Invalid refund amount or currency.")
    return action


def receipt(decision_id: str) -> dict:
    return {"id": decision_id, "status": "succeeded", "reference": f"practice-{decision_id}"}


def initialize_ledger(path: Path):
    # Create with private permissions before SQLite opens the file.
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(path)) as db:
        db.execute("""create table if not exists practice_decisions (
            tenant text not null, id text not null, action text not null,
            created_at text not null default current_timestamp, primary key (tenant, id)
        )""")


def record(path: Path, tenant: str, decision_id: str, action: dict) -> dict:
    content = json.dumps(action, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    # One transaction serializes competing deliveries, even across server restarts.
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("""insert into practice_decisions (tenant,id,action) values (?,?,?)
            on conflict (tenant,id) do nothing""", (tenant, decision_id, content))
        prior = db.execute("select action from practice_decisions where tenant=? and id=?",
                           (tenant, decision_id)).fetchone()
        if prior[0] != content:
            raise RequestError(409, "Decision ID already belongs to a different action.")
    return receipt(decision_id)


class PracticeServer(ThreadingHTTPServer):
    def __init__(self, port: int, path: Path, tenant: str, token: str):
        if not TENANT.fullmatch(tenant) or not TOKEN.fullmatch(token):
            raise ValueError("A tenant ID and valid MONOLITH_PRACTICE_CONNECTOR_TOKEN are required.")
        initialize_ledger(path)
        self.path = path
        self.tenant = tenant
        self.authorization = f"Bearer {token}".encode("ascii")
        super().__init__(("127.0.0.1", port), PracticeHandler)


class PracticeHandler(BaseHTTPRequestHandler):
    server: PracticeServer
    timeout = 5

    def log_message(self, _format, *_args):
        pass  # Requests can contain sensitive identifiers. Use the private receipt ledger.

    def read_decision(self):
        if self.path != "/monolith":
            raise RequestError(404, "Unknown endpoint.")
        auth = self.headers.get_all("Authorization", [])
        if len(auth) != 1 or not hmac.compare_digest(auth[0].encode("latin1"), self.server.authorization):
            raise RequestError(401, "Invalid credential.")
        keys = self.headers.get_all("Idempotency-Key", [])
        if len(keys) != 1 or not canonical_uuid(keys[0]):
            raise RequestError(422, "Expected one UUID as the idempotency key.")
        if self.headers.get_content_type() != "application/json":
            raise RequestError(415, "Expected application/json.")
        lengths = self.headers.get_all("Content-Length", [])
        if ("Transfer-Encoding" in self.headers or len(lengths) != 1
                or not re.fullmatch(r"[0-9]{1,8}", lengths[0])):
            raise RequestError(400, "Expected one bounded content length.")
        length = int(lengths[0])
        if length > MAX_BODY:
            raise RequestError(413, "Request body too large.")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise RequestError(400, "Incomplete request body.")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
        except (ValueError, RecursionError) as error:
            raise RequestError(400, "Invalid JSON.") from error
        if not isinstance(data, dict) or set(data) != {"id", "tenant", "action"} or data["id"] != keys[0]:
            raise RequestError(422, "Decision and idempotency key must agree.")
        if data["tenant"] != self.server.tenant:
            raise RequestError(403, "Wrong tenant.")
        return record(self.server.path, self.server.tenant, keys[0], validated_action(data["action"]))

    def do_POST(self):
        try:
            result = self.read_decision()
            status = 200
        except RequestError as error:
            result, status = {"error": str(error)}, error.status
        except UnicodeError:
            result, status = {"error": "Invalid Unicode."}, 422
        except sqlite3.Error:
            result, status = {"error": "Local rehearsal ledger unavailable."}, 503
        body = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Accept synthetic actions on loopback")
    serve.add_argument("--port", type=int, default=4177)
    lookup = commands.add_parser("receipt", help="Look up a previously rehearsed decision")
    lookup.add_argument("--id", required=True)
    for command in (serve, lookup):
        command.add_argument("--tenant", required=True)
        command.add_argument("--db", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "receipt":
            if not canonical_uuid(args.id) or not TENANT.fullmatch(args.tenant):
                parser.error("Invalid decision or tenant ID.")
            uri = args.db.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as db:
                found = db.execute("select 1 from practice_decisions where tenant=? and id=?",
                                   (args.tenant, args.id)).fetchone()
            if found:
                print(json.dumps(receipt(args.id)))
                return 0
            print("No receipt for that decision.", file=sys.stderr)
            return 1
        if not 1 <= args.port <= 65535:
            parser.error("Port must be between 1 and 65535.")
        token = os.environ.get("MONOLITH_PRACTICE_CONNECTOR_TOKEN", "")
        with PracticeServer(args.port, args.db, args.tenant, token) as server:
            print(f"Practice connector listening at http://127.0.0.1:{args.port}/monolith", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Practice connector: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
