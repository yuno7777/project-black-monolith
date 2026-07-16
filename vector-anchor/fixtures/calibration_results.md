# VectorAnchor — calibration results

_Reproduce with `python fixtures/calibrate.py` (deterministic hashing embedder)._

## Parameters under test

| Parameter | Value |
| :--- | ---: |
| `top_rank_threshold` (a doc must rank in the top-N) | 2 |
| `topic_similarity` (cosine ≥ ⇒ same topic) | 0.2 |
| `min_distinct_topics` (flag threshold) | 4 |
| `window_size` | 50 |

## False-positive test

18 diverse clean queries across six topics, clean corpus of 24 documents (no poison present).

| Clean document | Distinct-topic score | Flagged |
| :--- | ---: | :---: |
| garden-3 | 2 | no |
| garden-4 | 2 | no |
| astro-2 | 2 | no |
| cook-1 | 2 | no |
| cook-2 | 2 | no |
| cook-4 | 2 | no |
| fin-3 | 2 | no |
| fin-4 | 2 | no |
| _…16 more, all lower_ | | |

- **Highest clean-document score: 2**
- **Documents flagged: 0** 

## Separation vs. the poison fixture

| | Distinct-topic score |
| :--- | ---: |
| highest clean document | 2 |
| `min_distinct_topics` threshold | 4 |
| **poison fixture** | **4** |

- Threshold **4** sits above the highest clean score (**2**) with a margin of **2** and at/below the poison score (**4**), so the poison is flagged and no clean document is.

> Historical note: the original parameters `(top_rank_threshold=3, topic_similarity=0.30)` let a broad single-domain document (`garden-4`) reach a score of **7** — higher than the poison (5) — an unfixable overlap. Tightening to `(2, 0.20)` merges genuinely-related clean sub-topic queries while keeping the poison's truly-unrelated triggers separate, restoring separation.
