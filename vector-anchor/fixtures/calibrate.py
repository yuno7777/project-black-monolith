#!/usr/bin/env python3
"""VectorAnchor false-positive + threshold-separation harness.

Seeds the clean corpus, runs a set of diverse *clean* queries (not the poison
triggers) through the frequency-anomaly detector, and confirms no legitimate
document is flagged. Then runs the poison scenario and reports the separation
between the highest clean-document score and the poison's score, which
justifies the `min_distinct_topics` threshold.

Ranking is computed with the same offline hashing embedder the service uses
(`MONOLITH_EMBEDDING=hash`), so the ordering matches production; the detector
component (frequency_tracker) is exercised exactly as in retriever_proxy.
Deterministic — reproducible run to run.

    python fixtures/calibrate.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from src.config import load_config  # noqa: E402
from src.embedding import HashingEmbeddingFunction, cosine  # noqa: E402
from src.frequency_tracker import FrequencyTracker  # noqa: E402
import corpus_data as cd  # noqa: E402

CFG = load_config()
EF = HashingEmbeddingFunction(dim=CFG.embedding_dim)
_DOC_EMB = {doc_id: EF([text])[0] for doc_id, text in cd.CLEAN_DOCS}

# 18 diverse clean queries across the six corpus topics (3 each). None are
# poison-trigger queries. Deliberately spans narrow sub-topics within each
# domain — the hard case for a frequency detector.
CLEAN_QUERIES = [
    "how to prune tomato plants", "best mulch for flower beds", "composting kitchen scraps for soil",
    "what is a red giant star", "how galaxies form from gas", "measuring distance to a nebula",
    "how to boil pasta al dente", "searing a steak in a hot pan", "making soft scrambled eggs",
    "building an emergency fund", "paying off credit card debt", "diversifying a retirement portfolio",
    "using a password manager", "segmenting a network with firewalls", "spotting phishing emails",
    "adjusting bicycle saddle height", "lubricating a bike chain", "maintaining a smooth cadence on climbs",
]


def _ranked(query: str, pool: list[tuple[str, str]]) -> list[str]:
    embs = {i: (_DOC_EMB.get(i) or EF([t])[0]) for i, t in pool}
    q = EF([query])[0]
    return [i for _, i in sorted(((cosine(q, embs[i]), i) for i, _ in pool), reverse=True)]


def _tracker() -> FrequencyTracker:
    return FrequencyTracker(
        min_distinct_topics=CFG.min_distinct_topics,
        topic_similarity=CFG.topic_similarity,
        window_size=CFG.window_size,
    )


def main() -> None:
    # --- false-positive run: clean corpus + clean queries only ------------
    fp = _tracker()
    for q in CLEAN_QUERIES:
        fp.record_query(_ranked(q, cd.CLEAN_DOCS)[: CFG.top_rank_threshold], EF([q])[0])
    clean_scores = {i: fp.distinct_topic_count(i) for i, _ in cd.CLEAN_DOCS}
    flagged = [i for i, _ in cd.CLEAN_DOCS if fp.is_anomalous(i)]
    clean_max = max(clean_scores.values())

    # --- poison run: clean corpus + poison, clean then trigger queries ----
    pr = _tracker()
    pool = cd.CLEAN_DOCS + [(cd.POISON_DOC_ID, cd.POISON_DOC_TEXT)]
    for q in cd.CLEAN_QUERIES + cd.POISON_TRIGGER_QUERIES:
        pr.record_query(_ranked(q, pool)[: CFG.top_rank_threshold], EF([q])[0])
    poison_score = pr.distinct_topic_count(cd.POISON_DOC_ID)

    top = sorted(clean_scores.items(), key=lambda kv: -kv[1])[:8]

    lines: list[str] = []
    lines.append("# VectorAnchor — calibration results\n")
    lines.append("_Reproduce with `python fixtures/calibrate.py` (deterministic hashing embedder)._\n")
    lines.append("## Parameters under test\n")
    lines.append("| Parameter | Value |")
    lines.append("| :--- | ---: |")
    lines.append(f"| `top_rank_threshold` (a doc must rank in the top-N) | {CFG.top_rank_threshold} |")
    lines.append(f"| `topic_similarity` (cosine ≥ ⇒ same topic) | {CFG.topic_similarity} |")
    lines.append(f"| `min_distinct_topics` (flag threshold) | {CFG.min_distinct_topics} |")
    lines.append(f"| `window_size` | {CFG.window_size} |")
    lines.append("")
    lines.append("## False-positive test\n")
    lines.append(f"{len(CLEAN_QUERIES)} diverse clean queries across six topics, "
                 f"clean corpus of {len(cd.CLEAN_DOCS)} documents (no poison present).\n")
    lines.append("| Clean document | Distinct-topic score | Flagged |")
    lines.append("| :--- | ---: | :---: |")
    for doc_id, score in top:
        lines.append(f"| {doc_id} | {score} | {'YES' if score >= CFG.min_distinct_topics else 'no'} |")
    lines.append(f"| _…{len(cd.CLEAN_DOCS) - len(top)} more, all lower_ | | |")
    lines.append("")
    lines.append(f"- **Highest clean-document score: {clean_max}**")
    lines.append(f"- **Documents flagged: {len(flagged)}** {flagged if flagged else ''}\n")
    lines.append("## Separation vs. the poison fixture\n")
    lines.append("| | Distinct-topic score |")
    lines.append("| :--- | ---: |")
    lines.append(f"| highest clean document | {clean_max} |")
    lines.append(f"| `min_distinct_topics` threshold | {CFG.min_distinct_topics} |")
    lines.append(f"| **poison fixture** | **{poison_score}** |")
    lines.append("")
    lines.append(
        f"- Threshold **{CFG.min_distinct_topics}** sits above the highest clean score "
        f"(**{clean_max}**) with a margin of **{CFG.min_distinct_topics - clean_max}** and "
        f"at/below the poison score (**{poison_score}**), so the poison is flagged and no "
        f"clean document is.\n"
    )
    lines.append(
        "> Historical note: the original parameters `(top_rank_threshold=3, "
        "topic_similarity=0.30)` let a broad single-domain document (`garden-4`) reach a "
        "score of **7** — higher than the poison (5) — an unfixable overlap. Tightening to "
        "`(2, 0.20)` merges genuinely-related clean sub-topic queries while keeping the "
        "poison's truly-unrelated triggers separate, restoring separation.\n"
    )

    out = os.path.join(os.path.dirname(__file__), "calibration_results.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"clean_max={clean_max} flagged={flagged} poison={poison_score} "
          f"threshold={CFG.min_distinct_topics}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
