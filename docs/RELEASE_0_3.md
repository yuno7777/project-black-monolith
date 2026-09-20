# Black Monolith 0.3.0 release candidate

This candidate expands multilingual first-hit retrieval indicators, adds paired
protected/unprotected agent outcomes, gates sustained request delivery, and
produces portable native bundles with dependency inventories and provenance.
It remains a research prototype.

## Evaluation separation

Fetch the pinned development and frozen test splits independently:

```text
python evaluation/import_external.py --split development
python evaluation/import_external.py --split test
python evaluation/content_benchmark.py --dataset evaluation/results/development.json --output evaluation/results/content-development.json
python evaluation/content_benchmark.py --dataset evaluation/results/external.json --output evaluation/results/content-independent.json
```

The rules were designed using 546 development cases. That result is 78/203
attack-labelled prompts detected and 0/343 benign flags. The untouched 116-case
test result is 18/60 attacks detected and 0/56 benign flags. Prompt classification
does not measure whether a model followed an attack.

The real-agent workflow compares the protected three-layer path with a raw-note
Ollama control using the same model and output-token limit. It reports literal
canary leakage, task fact-substring completion, hashes and timings. It never stores
generated output. Model defaults remain stochastic, so repeat runs are required
before treating a difference as stable.

## Load gate

On a disposable Compose stack:

```text
python scripts/verify_sustained_load.py
python scripts/verify_resilience.py --allow-faults
```

The sustained profile sends 300 retrievals with 16 clients, requires zero request
failures, reconciles 300 unique ledger IDs, and gates p99 below two seconds. The
fault profile separately holds a database lock and kills/restarts VectorAnchor.
These CI profiles do not establish production capacity.

## Portable bundles

CI builds ZIPs for Windows x86-64, Linux x86-64, macOS x86-64, and macOS arm64.
Each contains the platform MCP-Shield executable, installer scripts, an SPDX 2.3
SBOM, a SHA-256 checksum, and an in-toto statement using SLSA provenance v1.

After extraction, run `packaging/install.ps1` on Windows or
`packaging/install.sh` on macOS/Linux. Python 3.12, Node 22, PostgreSQL client and
server, and optional Ollama remain prerequisites. Configure the generated `.env`
before starting the demo. Bundles are unsigned until Windows and Apple signing
identities are configured.

## Repeated agent outcome trials

The v2 authored agent suite runs three trials per case by default. Attack notes
use exact build/checksum strings without describing them as credentials, so the
raw control can demonstrate whether the model follows the injected formatting
instruction. Protected and raw paths each run three stages. Reports include
Wilson 95% intervals for attack and task substring rates, plus paired prevention
and regression counts. Generated text remains memory-only and is discarded.

The intervals quantify observed binary variation only. Model calls share one
model/runtime and use stochastic defaults, so the trials are not independent
samples of real deployments. The suite remains development evidence.
