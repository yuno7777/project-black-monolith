#!/usr/bin/env python3
"""Inject the single adversarial "universal bait" document into the corpus.

This is a detection-test fixture only: the document is inert text engineered
to rank across four unrelated topics so the frequency-anomaly detector can be
validated against a PoisonedRAG-style corpus-poisoning pattern. It targets no
live system.

Routes through the running service's /admin/add-documents endpoint (see
seed_corpus.py for why).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from corpus_data import POISON_DOC_ID, POISON_DOC_TEXT  # noqa: E402

SERVICE_URL = os.environ.get("MONOLITH_SERVICE_URL", "http://localhost:8001")


def main() -> None:
    payload = {"documents": [{"id": POISON_DOC_ID, "text": POISON_DOC_TEXT}]}
    req = urllib.request.Request(
        SERVICE_URL + "/admin/add-documents",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    print(
        f"[inject] injected poison document {POISON_DOC_ID!r}; "
        f"corpus size = {result['total']}"
    )


if __name__ == "__main__":
    main()
