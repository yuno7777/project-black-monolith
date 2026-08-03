"""Atomic persistence for VectorAnchor's rolling detector and quarantine."""

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
        window_size: int,
    ) -> None:
        self.path = Path(path)
        self.min_distinct_topics = min_distinct_topics
        self.topic_similarity = topic_similarity
        self.window_size = window_size
        self.policy = {
            "min_distinct_topics": min_distinct_topics,
            "topic_similarity": topic_similarity,
            "window_size": window_size,
        }

    def load(self) -> tuple[FrequencyTracker, Quarantine] | None:
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
            window_size=self.window_size,
        )
        quarantine = Quarantine.from_snapshot(quarantine_data)
        return tracker, quarantine

    def save(self, tracker: FrequencyTracker, quarantine: Quarantine) -> None:
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
