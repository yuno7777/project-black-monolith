"""Atomic persistence for VectorAnchor's rolling detector and quarantine.

WHAT THIS FILE IS
-----------------
The save/load layer for the detector's memory. VectorAnchor's FrequencyTracker
and Quarantine live in RAM while the service runs; this class writes them to a
JSON file on disk (detector_state.json, on a Docker volume) after every
mutation and restores them at startup.

WHY IT EXISTS
-------------
The poison detector's verdicts are accumulated EVIDENCE. If the container
restarts and the tracker forgets the 300 queries it already saw, a bait
document that was one query away from detection gets a fresh start — the
attacker only needs the service to restart. Persisting the state keeps the
detection continuous across restarts.

WHY "ATOMIC"
------------
The naive way to save is truncate-and-write, which can leave a corrupt or
empty file if the process dies mid-write. This class writes to a sibling
".tmp" file, fsyncs it, then renames it over the target — rename within a
directory is atomic, so the file on disk is always either the old complete
state or the new complete state, never a torn mix.

Security note: the file on disk is treated as UNTRUSTED input on load (someone
with access to the volume could edit it). load() validates everything — size,
version, policy match, field types — and raises ValueError on anything wrong,
which main.py handles by moving the file aside and starting fresh.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .frequency_tracker import FrequencyTracker
from .quarantine import Quarantine

MAX_STATE_BYTES = 32 * 1024 * 1024


class DetectorStateStore:
    def __init__(
        self,
        path: str,
        *,
        min_distinct_topics: int,
        topic_similarity: float,
        retention_horizon: int,
        max_queries_per_doc: int,
    ) -> None:
        """Called from main.py build_proxy(). Remembers the CURRENT detector
        policy so load() can detect a file written under different thresholds
        (whose scores would mean something else) and refuse it."""
        self.path = Path(path)
        self.min_distinct_topics = min_distinct_topics
        self.topic_similarity = topic_similarity
        self.retention_horizon = retention_horizon
        self.max_queries_per_doc = max_queries_per_doc
        self.policy = {
            "min_distinct_topics": min_distinct_topics,
            "topic_similarity": topic_similarity,
            "retention_horizon": retention_horizon,
            "max_queries_per_doc": max_queries_per_doc,
        }

    def quarantine_unreadable(self) -> str:
        """Move state that cannot be loaded aside instead of deleting it.

        Called when the persisted policy or schema no longer matches. The file
        is evidence of what the detector had seen, so it is preserved for
        inspection rather than overwritten by the next save. The next save
        writes a fresh file at the original path. Returns the new path so
        main.py can log where the old state went.
        """
        target = self.path.with_suffix(self.path.suffix + ".unreadable")
        if target.exists():
            target.unlink()
        os.replace(self.path, target)
        return str(target)

    def load(self) -> tuple[FrequencyTracker, Quarantine] | None:
        """Restore tracker + quarantine from disk. Returns None if no file
        exists yet. Raises ValueError on anything unreadable/invalid — main.py
        catches that, quarantines the file, and starts empty.

        Validation steps:
          1. size <= 32 MiB
          2. top-level object with version == 1
          3. stored policy == current policy (different thresholds -> refuse;
             scores under mixed rules are not reproducible)
          4. tracker and quarantine fields present with right shapes
          5. FrequencyTracker.from_snapshot + Quarantine.from_snapshot do their
             own deep field validation.
        """
        if not self.path.exists():
            return None
        if self.path.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("detector state exceeds 32 MiB")
        with self.path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("unsupported detector state")
        if data.get("policy") != self.policy:
            raise ValueError(
                "persisted detector state uses different policy thresholds; reset it explicitly"
            )
        tracker_data = data.get("tracker")
        quarantine_data = data.get("quarantine")
        if not isinstance(tracker_data, dict) or not isinstance(quarantine_data, list):
            raise ValueError("detector state payload is incomplete")
        tracker = FrequencyTracker.from_snapshot(
            tracker_data,
            min_distinct_topics=self.min_distinct_topics,
            topic_similarity=self.topic_similarity,
            retention_horizon=self.retention_horizon,
            max_queries_per_doc=self.max_queries_per_doc,
        )
        quarantine = Quarantine.from_snapshot(quarantine_data)
        return tracker, quarantine

    def save(self, tracker: FrequencyTracker, quarantine: Quarantine) -> None:
        """Atomically write the current detector state.

        Called from: retriever_proxy.py _persist_state(), i.e. after EVERY
        /retrieve and after every admin mutation. The file is small (capped at
        32 MiB) and the write is a temp-file + fsync + rename, so this is cheap
        and safe on the hot path.

        Step by step:
          1. Build the JSON payload (tracker.snapshot() + quarantine.snapshot()
             + the policy, so load() can verify it later).
          2. Enforce the size cap (raising means the caller's save is skipped
             and the error surfaces — better than writing a giant file).
          3. Write to <path>.tmp, flush + fsync (data actually on disk).
          4. os.replace(tmp, path) — atomic rename.
        """
        payload = json.dumps(
            {
                "version": 1,
                "policy": self.policy,
                "tracker": tracker.snapshot(),
                "quarantine": quarantine.snapshot(),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_STATE_BYTES:
            raise ValueError("detector state exceeds 32 MiB")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
