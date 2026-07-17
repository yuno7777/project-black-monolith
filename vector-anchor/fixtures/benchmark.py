"""What does VectorAnchor's detection cost per retrieval?

Measures the *detector*, not the vector search: the embedding lookup and
ChromaDB query happen with or without this project, so charging them to the
defense would flatter it. What the defense adds is the frequency tracker —
recording each query and clustering a document's history to count topics — so
that is what is timed.

The tracker is filled to a full rolling window first. An empty tracker is the
best case and nobody runs in the best case; the steady state is a full window,
which is also where the clustering is most expensive.

Run from the module root:  python fixtures/benchmark.py
"""

from __future__ import annotations

import random
import statistics
import sys
import time

sys.path.insert(0, ".")

from src.frequency_tracker import FrequencyTracker  # noqa: E402

WINDOW = 50
MIN_DISTINCT_TOPICS = 4
TOPIC_SIMILARITY = 0.20
DIM = 256  # matches MONOLITH_EMBEDDING_DIM
ITERATIONS = 2_000
CORPUS = 24  # matches the seeded demo corpus


def embedding(rng: random.Random) -> list[float]:
    return [rng.random() for _ in range(DIM)]


def measure() -> dict[str, float]:
    """Return the per-retrieval detector overhead percentiles, in microseconds.

    Exposed so the detection benchmark can fold latency into its report without
    re-implementing the measurement.
    """
    rng = random.Random(20260717)  # fixed seed: reproducible run to run
    tracker = FrequencyTracker(
        min_distinct_topics=MIN_DISTINCT_TOPICS,
        topic_similarity=TOPIC_SIMILARITY,
        window_size=WINDOW,
    )
    doc_ids = [f"doc-{i}" for i in range(CORPUS)]

    # Warm to the steady state: a full window, every document with history.
    for _ in range(WINDOW):
        tracker.record_query(rng.sample(doc_ids, 2), embedding(rng))

    samples: list[float] = []
    for _ in range(ITERATIONS):
        ranked = rng.sample(doc_ids, 2)
        emb = embedding(rng)
        start = time.perf_counter()
        # Exactly what retriever_proxy does per retrieval: record the query,
        # then test every returned document for the anomaly.
        tracker.record_query(ranked, emb)
        for doc_id in ranked:
            tracker.is_anomalous(doc_id)
        samples.append((time.perf_counter() - start) * 1_000_000)

    samples.sort()
    return {
        "mean": statistics.mean(samples),
        "median": statistics.median(samples),
        "p50": statistics.median(samples),
        "p95": samples[int(len(samples) * 0.95)],
        "p99": samples[int(len(samples) * 0.99)],
        "max": samples[-1],
    }


def main() -> None:
    m = measure()
    print(f"VectorAnchor — detector overhead per retrieval (N={ITERATIONS})")
    print(f"  window={WINDOW}  corpus={CORPUS}  embedding_dim={DIM}")
    print()
    print(f"  mean    {m['mean']:8.1f} us")
    print(f"  median  {m['median']:8.1f} us")
    print(f"  p95     {m['p95']:8.1f} us")
    print(f"  p99     {m['p99']:8.1f} us")
    print(f"  max     {m['max']:8.1f} us")


if __name__ == "__main__":
    main()
