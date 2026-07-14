# VectorAnchor

**Project Black Monolith — memory-layer defense (Module 2 of 3)**

VectorAnchor wraps a vector-database retriever and defends an agent's memory
layer against **corpus poisoning**. The specific pattern it catches is a
"universal bait" document (à la PoisonedRAG): a single adversarial document
engineered to rank highly for many *unrelated* queries, so it gets pulled
into the agent's context no matter what the agent is actually asking about.

The insight: a legitimate document is relevant to one topic and only ranks
for queries about that topic. A universal-bait document ranks across many
**mutually dissimilar** queries. So the signal isn't raw retrieval frequency
— it's *breadth across dissimilar queries*. VectorAnchor tracks, per
document, how many distinct topics (clusters of similar queries) it has
ranked highly for within a rolling window; crossing the threshold quarantines
it and serves the next-best clean result instead.

## How it works

```text
  agent ──POST /retrieve──▶ VectorAnchor ──query──▶ ChromaDB
                              │  RetrieverProxy
                              │   ├─ FrequencyTracker: cluster the queries each
                              │   │    doc ranks for; count distinct topics
                              │   ├─ Quarantine: withhold flagged docs
                              │   └─ next-best clean docs returned to caller
  agent ◀──clean results─────┘
        (poisoned doc never reaches the context window)
```

- `src/retriever_proxy.py` — the choke point every retrieval passes through.
- `src/frequency_tracker.py` — pure-Python anomaly detector (no ChromaDB
  dependency, so it is unit-testable in isolation).
- `src/quarantine.py` — in-memory flagged-document store.
- `src/embedding.py` — the embedding function (see design note below).
- `src/store.py` — ChromaDB collection helpers.
- `src/events.py` — structured event emission in the shared Project Black
  Monolith shape + best-effort dashboard forwarding.
- `src/main.py` — FastAPI app.

## Design decisions (noted for the reviewer)

- **Embedding function.** The default is a lightweight, dependency-free,
  deterministic **hashing bag-of-words embedder** (`MONOLITH_EMBEDDING=hash`).
  It needs no model download, so the demo runs fully offline and reproducibly,
  and cosine similarity under it tracks shared vocabulary — which is exactly
  what lets an engineered bait document (stuffed with many topics' terms) rank
  broadly and be caught. Set `MONOLITH_EMBEDDING=default` to use ChromaDB's
  built-in sentence-transformers embedder for real semantic quality (heavier;
  downloads a model on first use). The detector logic is identical either way.
- **ChromaDB runs embedded** (`PersistentClient`), so there is no separate
  vector-DB service to run. The FastAPI service owns the single ChromaDB
  client; the seed/inject fixtures add documents through
  `POST /admin/add-documents` rather than opening a second client (which would
  contend on ChromaDB's SQLite store).
- **Quarantine is in-memory** — this is a single-operator local research/demo
  system; a restart re-learns from the live stream.

## Endpoints

| Method + path              | Purpose                                            |
| -------------------------- | -------------------------------------------------- |
| `GET  /health`             | liveness + corpus/quarantine counts                |
| `POST /retrieve`           | `{query, k?}` → clean top-k results (agent-facing) |
| `GET  /quarantine`         | list of quarantined documents                      |
| `GET  /stats`              | detector configuration + counts                    |
| `POST /admin/add-documents`| bulk insert/upsert (used by fixtures)              |
| `POST /admin/reset-detection` | clear tracker + quarantine (not the corpus)     |

## Configuration (environment variables)

| Variable                     | Default            | Purpose                                             |
| ---------------------------- | ------------------ | --------------------------------------------------- |
| `MONOLITH_EMBEDDING`         | `hash`             | `hash` (offline, deterministic) or `default` (ST)   |
| `MONOLITH_CHROMA_PATH`       | `./chroma_store`   | embedded ChromaDB persistence directory             |
| `MONOLITH_TOP_K`             | `3`                | results returned to the caller                      |
| `MONOLITH_TOP_RANK_THRESHOLD`| `3`                | a doc "ranks highly" if in the top this-many        |
| `MONOLITH_MIN_DISTINCT_TOPICS`| `4`               | distinct topics before a doc is quarantined         |
| `MONOLITH_TOPIC_SIMILARITY`  | `0.30`             | queries at/above this cosine count as one topic     |
| `MONOLITH_WINDOW_SIZE`       | `50`               | rolling window (number of recent queries)           |
| `MONOLITH_DASHBOARD_URL`     | *(unset)*          | if set, events are also POSTed here                 |

## Setup & demo

```sh
cd vector-anchor
pip install -r requirements.txt

# End-to-end corpus-poisoning detection demo (starts the service, seeds a
# clean corpus, runs clean queries, injects the bait, triggers detection):
bash fixtures/run_demo.sh

# Unit tests for the anomaly detector (no ChromaDB needed):
python -m pytest tests/
```

Expected demo outcome: clean queries flag nothing; after the fourth unrelated
query retrieves the injected document it is quarantined (`anomaly score = 4`),
withheld from subsequent results, and a `corpus_poison_quarantine` event
fires. The script prints `DEMO PASSED`.

## Known limitations

- Detection is retrieval-driven: a bait document is only flagged once it has
  actually ranked across enough dissimilar queries. A document that has not
  yet been broadly retrieved is not pre-emptively flagged.
- The hashing embedder is intentionally simple (shared-vocabulary similarity).
  Adversarial paraphrase attacks that avoid vocabulary overlap are better
  handled by the `default` semantic embedder; swapping it in is one env var.
- Quarantine and frequency state are per-process and reset on restart.
