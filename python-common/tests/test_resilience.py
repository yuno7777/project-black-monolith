"""Bounded queues and crash durability under concurrent production."""

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from monolith_events.events import EventOutbox


def make(path, **kwargs):
    return EventOutbox(
        str(path),
        "http://127.0.0.1:9999/api/ingest",
        "test-token-value",
        start_worker=False,
        **kwargs,
    )


def test_concurrent_queue_pressure_is_bounded_and_reopens(tmp_path):
    path = tmp_path / "queue.db"
    queue = make(path, max_pending=100, max_dead=25)
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(lambda i: queue.enqueue(f"e-{i}", b"{}"), range(1000)))
    assert queue.stats()["pending"] == 100
    assert queue.stats()["dead"] == 25
    queue.close()
    queue = make(path, max_pending=100, max_dead=25)
    assert queue.stats()["pending"] == 100
    queue._post = lambda _: (200, "")
    for _ in range(7):
        queue.flush_once()
    assert queue.stats()["pending"] == 0
    queue.close()


def test_slow_collector_does_not_hold_producer_lock(tmp_path):
    queue = make(tmp_path / "queue.db")
    entered, release = threading.Event(), threading.Event()

    def slow(_):
        entered.set()
        assert release.wait(5)
        return 200, ""

    queue._post = slow
    queue.enqueue("first", b"{}")
    with ThreadPoolExecutor(max_workers=2) as workers:
        consumer = workers.submit(queue.flush_once)
        try:
            assert entered.wait(3)
            workers.submit(queue.enqueue, "second", b"{}").result(timeout=1)
        finally:
            release.set()
        consumer.result(timeout=3)
    assert queue.stats()["pending"] == 1
    queue.close()


def test_committed_events_survive_abrupt_process_exit(tmp_path):
    path = tmp_path / "crash.db"
    code = """
import os,sys
from monolith_events.events import EventOutbox
q=EventOutbox(sys.argv[1], 'http://127.0.0.1:9999/api/ingest', 'test-token-value', start_worker=False)
for i in range(20): q.enqueue(str(i), b'{}')
os._exit(9)
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    result = subprocess.run([sys.executable, "-c", code, str(path)], env=env, timeout=10)
    assert result.returncode == 9
    queue = make(path)
    assert queue.stats()["pending"] == 20
    delivered = []
    queue._post = lambda payload: (delivered.append(payload) or 200, "")
    queue.flush_once()
    queue.flush_once()
    assert len(delivered) == 20
    assert queue.stats()["pending"] == 0
    queue.close()


def test_sqlite_capacity_exhaustion_preserves_backlog_and_recovers(tmp_path):
    import sqlite3

    import pytest

    queue = make(tmp_path / "full.db")
    queue.enqueue("before", b"{}")
    pages = queue._connection.execute("pragma page_count").fetchone()[0]
    queue._connection.execute(f"pragma max_page_count={pages}")
    with pytest.raises(sqlite3.OperationalError, match="full"):
        queue.enqueue("too-large", b"x" * 16000)
    assert queue.stats()["pending"] == 1
    queue._connection.execute("pragma max_page_count=1000")
    queue.enqueue("after", b"{}")
    delivered = []
    queue._post = lambda payload: (delivered.append(payload) or 200, "")
    queue.flush_once()
    assert len(delivered) == 2
    assert queue.stats()["pending"] == 0
    queue.close()


def test_backlog_survives_repeated_restarts(tmp_path):
    path = tmp_path / "restart.db"
    for cycle in range(5):
        queue = make(path)
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(workers.map(lambda i, queue=queue, cycle=cycle: queue.enqueue(f"{cycle}-{i}", b"{}"), range(100)))
        assert queue.stats()["pending"] == (cycle + 1) * 100
        queue.close()
    queue = make(path)
    delivered = []
    queue._post = lambda payload: (delivered.append(payload) or 200, "")
    while queue.stats()["pending"]:
        queue.flush_once()
    assert len(delivered) == 500
    queue.close()
