"""Gate sustained retrieval load against a disposable Compose stack."""

import argparse
import json
import os
import statistics
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from run_local_demo import ROOT, load_env, post
from verify_session import get


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--max-p99-ms", type=float, default=2000)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "evaluation/results/sustained-load.json"
    )
    args = parser.parse_args()
    if not 1 <= args.requests <= 500 or not 1 <= args.concurrency <= 64:
        raise ValueError("requests must be 1-500 and concurrency 1-64")
    env = load_env(ROOT / ".env", dict(os.environ))
    session = "sustained-" + uuid.uuid4().hex
    env.update(MONOLITH_SESSION_ID=session, MONOLITH_AGENT_ID="sustained-load-probe")

    def retrieve(index):
        started = time.perf_counter()
        post(
            "http://127.0.0.1:8001/retrieve",
            {"query": f"Sustained gardening request {index % 20}"},
            context=env,
        )
        return (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    latencies = []
    failures = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(retrieve, index): index for index in range(args.requests)}
        for future in as_completed(futures):
            try:
                latencies.append(future.result())
            except Exception as error:
                failures.append({"index": futures[future], "error": type(error).__name__})
    duration = time.perf_counter() - started
    if failures:
        raise RuntimeError(f"{len(failures)} retrieval requests failed")

    query = urllib.parse.urlencode({"session": session, "status": "all", "limit": 500})
    deadline = time.monotonic() + 45
    retrievals = []
    while time.monotonic() < deadline:
        events = get(
            "http://127.0.0.1:3000/api/incidents?" + query,
            env["MONOLITH_OPERATOR_TOKEN"],
        )["incidents"]
        retrievals = [event for event in events if event["event_type"] == "retrieval"]
        if len(retrievals) == args.requests:
            break
        time.sleep(0.25)
    if len(retrievals) != args.requests:
        raise RuntimeError(f"Ledger has {len(retrievals)}/{args.requests} retrieval events")
    unique = len({event["event_id"] for event in retrievals})
    if unique != args.requests:
        raise RuntimeError("Duplicate ledger event IDs under sustained load")

    p99 = percentile(latencies, 0.99)
    result = {
        "requests": args.requests,
        "concurrency": args.concurrency,
        "failures": 0,
        "duration_seconds": duration,
        "throughput_requests_per_second": args.requests / duration,
        "latency_ms": {
            "mean": statistics.mean(latencies),
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": p99,
            "max": max(latencies),
        },
        "persisted_unique_events": unique,
        "session_id": session,
        "gate": {"max_p99_ms": args.max_p99_ms, "passed": p99 <= args.max_p99_ms},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    if p99 > args.max_p99_ms:
        raise RuntimeError(f"p99 {p99:.1f} ms exceeds {args.max_p99_ms:.1f} ms")


if __name__ == "__main__":
    main()
