#!/usr/bin/env python3
"""VectorAnchor detection-accuracy benchmark.

Scores the frequency-anomaly detector over a labelled corpus and emits a
confusion matrix (TP/FP/TN/FN) with the derived detection rate, false-positive
rate, precision, recall and F1 — plus the per-retrieval latency folded in from
`benchmark.py`.

  Positives = universal-bait documents (POISON_SCENARIOS), each injected into
              the clean corpus and evaluated after its trigger queries run.
  Negatives = the clean documents, evaluated once in a benign scenario (diverse
              clean queries + the hard-negative gardening battery). None should
              be flagged.

Deterministic — same hashing embedder and detector the service uses, so the
numbers reproduce run to run. Writes `benchmark_results.json` for the uploader
and exits non-zero if the gates are not met (so CI can depend on it).

    python fixtures/benchmark_detection.py
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from src.config import load_config  # noqa: E402
from src.embedding import HashingEmbeddingFunction, cosine  # noqa: E402
from src.frequency_tracker import FrequencyTracker  # noqa: E402
import corpus_data as cd  # noqa: E402
import benchmark as latency  # noqa: E402

BENCHMARK_VERSION = 1

# Gates. These prevent regression; they are set at or just below what the
# calibrated detector actually achieves, not at an aspirational 100%.
MIN_DETECTION_RATE = 0.70   # the subtle bait (scenario D) is expected to evade
MAX_FALSE_POSITIVE_RATE = 0.0  # no clean document may be flagged

CFG = load_config()
EF = HashingEmbeddingFunction(dim=CFG.embedding_dim)

# The same 18 diverse clean queries the calibration uses, plus the hard-negative
# gardening battery, so the benign scenario stresses the false-positive surface.
BENIGN_QUERIES = [
    "how to prune tomato plants", "best mulch for flower beds", "composting kitchen scraps for soil",
    "what is a red giant star", "how galaxies form from gas", "measuring distance to a nebula",
    "how to boil pasta al dente", "searing a steak in a hot pan", "making soft scrambled eggs",
    "building an emergency fund", "paying off credit card debt", "diversifying a retirement portfolio",
    "using a password manager", "segmenting a network with firewalls", "spotting phishing emails",
    "adjusting bicycle saddle height", "lubricating a bike chain", "maintaining a smooth cadence on climbs",
] + cd.HARD_NEGATIVE_QUERIES


def ranked(query: str, pool: list[tuple[str, str]]) -> list[str]:
    embs = {i: EF([t])[0] for i, t in pool}
    q = EF([query])[0]
    return [i for _, i in sorted(((cosine(q, embs[i]), i) for i, _ in pool), reverse=True)]


def tracker() -> FrequencyTracker:
    return FrequencyTracker(
        min_distinct_topics=CFG.min_distinct_topics,
        topic_similarity=CFG.topic_similarity,
        window_size=CFG.window_size,
    )


def main() -> None:
    tp = fn = fp = tn = 0
    detail: list[dict] = []

    # --- positives: each bait scenario, evaluated after its triggers ---------
    for doc_id, text, triggers in cd.POISON_SCENARIOS:
        pool = cd.CLEAN_DOCS + [(doc_id, text)]
        t = tracker()
        # A few benign queries first, then the bait's triggers — the realistic
        # order in which a bait accumulates its cross-topic hits.
        for q in cd.CLEAN_QUERIES + triggers:
            t.record_query(ranked(q, pool)[: CFG.top_rank_threshold], EF([q])[0])
        flagged = t.is_anomalous(doc_id)
        score = t.distinct_topic_count(doc_id)
        if flagged:
            tp += 1
        else:
            fn += 1
        detail.append({"doc": doc_id, "label": "attack", "flagged": flagged, "topics": score})

    # --- negatives: clean corpus, benign queries, no poison present ----------
    t = tracker()
    for q in BENIGN_QUERIES:
        t.record_query(ranked(q, cd.CLEAN_DOCS)[: CFG.top_rank_threshold], EF([q])[0])
    for doc_id, _ in cd.CLEAN_DOCS:
        if t.is_anomalous(doc_id):
            fp += 1
            detail.append({"doc": doc_id, "label": "clean", "flagged": True,
                           "topics": t.distinct_topic_count(doc_id)})
        else:
            tn += 1

    detection_rate = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = detection_rate
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    report = {
        "benchmark_version": BENCHMARK_VERSION,
        "run_at_ms": int(time.time() * 1000),
        "module": "vector-anchor",
        "detector": "frequency_anomaly",
        "paradigm": "threshold",
        "corpus": {"attack_samples": tp + fn, "benign_samples": fp + tn},
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "detection_rate": round(detection_rate, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "latency_us": {k: round(v, 1) for k, v in latency.measure().items()
                       if k in ("p50", "p95", "p99")},
        "thresholds": {
            "min_distinct_topics": CFG.min_distinct_topics,
            "topic_similarity": CFG.topic_similarity,
            "top_rank_threshold": CFG.top_rank_threshold,
            "window_size": CFG.window_size,
        },
        "notes": ("Positives are engineered universal-bait documents; scenario D "
                  "is a deliberately subtle bait expected to evade, so a detection "
                  "rate below 100% is the honest result. Negatives include the "
                  "broad single-domain hard negative (garden-*)."),
    }

    out = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump([report], f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\nwrote {out}")
    for d in detail:
        mark = "caught" if d["flagged"] else "missed"
        print(f"  {d['label']:6} {d['doc']:22} topics={d['topics']} -> {mark}")

    # --- gates ---------------------------------------------------------------
    ok = True
    if detection_rate < MIN_DETECTION_RATE:
        print(f"\nGATE FAIL: detection rate {detection_rate:.2f} < {MIN_DETECTION_RATE}")
        ok = False
    if fpr > MAX_FALSE_POSITIVE_RATE:
        print(f"\nGATE FAIL: false-positive rate {fpr:.2f} > {MAX_FALSE_POSITIVE_RATE}")
        ok = False
    if not ok:
        sys.exit(1)
    print(f"\nGATES PASS: detection {detection_rate:.0%}, FPR {fpr:.0%}")


if __name__ == "__main__":
    main()
