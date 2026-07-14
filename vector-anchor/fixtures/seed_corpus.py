#!/usr/bin/env python3
"""Seed the VectorAnchor corpus with the clean demo documents.

Routes documents through the running service's /admin/add-documents endpoint
so the service stays the single owner of the ChromaDB client (avoids
cross-process SQLite contention). Set MONOLITH_SERVICE_URL to point at the
service (default http://localhost:8001).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from corpus_data import CLEAN_DOCS  # noqa: E402

SERVICE_URL = os.environ.get("MONOLITH_SERVICE_URL", "http://localhost:8001")


def post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        SERVICE_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> None:
    payload = {"documents": [{"id": doc_id, "text": text} for doc_id, text in CLEAN_DOCS]}
    result = post("/admin/add-documents", payload)
    print(f"[seed] added {result['added']} clean documents; corpus size = {result['total']}")


if __name__ == "__main__":
    main()
