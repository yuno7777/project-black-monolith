# Black Monolith 0.2.0 release candidate

This source release adds first-retrieval instruction indicators, independently
sourced evaluation, a three-stage protected note workflow, and resilience tests.
It is a research prototype, not a guarantee against prompt injection.

## Install on Windows, macOS, or Linux

Install Python 3.12, Node 22, Rust 1.86, and PostgreSQL 16 or 17. Put `psql`
on PATH. From an extracted source archive or Git checkout:

```text
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in PowerShell, or
`source .venv/bin/activate` on macOS/Linux. Then:

```text
python -m pip install --require-hashes -r vector-anchor/requirements.lock -r trace-audit/requirements.lock
npm ci --prefix dashboard
cargo build --locked --manifest-path mcp-shield/Cargo.toml
python scripts/generate_secrets.py
```

Set `DATABASE_ADMIN_URL` and `DATABASE_URL` in `.env` to your local PostgreSQL
admin and runtime connections. The runtime password must match
`MONOLITH_DATABASE_RUNTIME_PASSWORD`; percent-encode special characters in URLs.
The bootstrap creates the restricted runtime role. Example URL structure:
`postgresql://postgres:YOUR_PASSWORD@127.0.0.1:5432/postgres`.
Never copy an administrative connection into `DATABASE_URL`.

```text
python scripts/run_local_demo.py
```

For real inference, install Ollama and pull `qwen2.5:0.5b`; set
`MONOLITH_OLLAMA_MODEL=qwen2.5:0.5b` in `.env`, then:

```text
python scripts/run_local_demo.py --backend ollama --skip-attacks --agent-demo
```

The workflow drafts, checks, and finalizes using bounded read-only tool calls,
retrieval, and audited generation. A detector termination stops subsequent steps.
The session report stores hashes and timings, not generated text. Use fresh
agent state when verifying first-contact events; persistent baselines are not
silently reset. Inspect the printed session ID in the dashboard.

## Reproduce evidence

```text
python -m pip install pyarrow==21.0.0
python evaluation/import_external.py
python evaluation/content_benchmark.py --dataset evaluation/results/external.json --output evaluation/results/content-independent.json
python evaluation/redaction_stress.py
python evaluation/real_models.py vector --output evaluation/results/semantic-real.json
python evaluation/real_models.py trace --model qwen2.5:0.5b --external evaluation/results/external.json --output evaluation/results/qwen-real.json
```

The independent test split is pinned to deepset/prompt-injections revision
`4f61ecb038e9c3fb77e21034b22511b523772cdd`. Its 116 test rows are never used for
calibration. Upstream metadata lists Apache-2.0 at the top level and CC-BY-4.0
inside dataset_info; the importer preserves both and attribution. Data is fetched
separately rather than redistributed in the source release.

The initial independent content-rule evaluation detected 1/60 attack-labelled
prompts with 0/56 benign false positives. These deliberately narrow rules are
supplemental indicators, not a general injection classifier. No thresholds were
tuned on this test split. Real-model prompts include 16 hash-selected external
test cases plus the authored evaluation; model outputs are stochastic, and attack
prompt detection does not prove attack success or prevention.

The fragmentation stress report gates contiguous single-layer Base64, hex, and
percent-encoded secrets. Decoding is bounded to 4,096 characters per atom and
never recursive; nested or arbitrarily separated encodings remain gaps. Plain, spaced, zero-width, and full-width AWS-key variants must not
leak. Long benign identifiers may be withheld by the fail-closed length policy.

Run faults only against a disposable Compose stack:

```text
python scripts/verify_resilience.py --allow-faults
```

This locks the event table for five seconds, runs eight concurrent clients,
kills/restarts VectorAnchor, and verifies all 33 retrieval events persist exactly
once in the ledger. Unit tests additionally check a 1,000-event burst against
queue bounds, nonblocking production with a slow collector, and abrupt-process
crash durability. These tests do not establish production capacity.

## Build and verify an archive

From a committed Git checkout:

```text
python scripts/package_release.py --version 0.2.0-rc.1
```

The ZIP contains committed source only, normalized ZIP timestamps/modes, and a
per-file SHA-256 manifest. A sibling checksum verifies the entire archive.
The release workflow builds it twice and requires identical bytes. It does not
bundle runtimes, models, credentials, or claim reproducible compiled binaries.


## Follow-up enforcement checks

TraceAudit policy version 3 reduces the default look-behind from 512 to 256
characters. Long candidates still fail closed, which can withhold benign long
identifiers. Boundary tests exercise fragmented encodings around release points;
this is a latency/false-positive tradeoff, not arbitrary secret detection.

Run the authored adversarial agent development cases against a native stack:

```text
python scripts/run_local_demo.py --backend ollama --skip-attacks --agent-evaluation
```

Six cases measure literal canary leakage across all three stages and final-answer
fact substrings, separately from detector flags. Reports contain hashes and
outcomes, not generated text. This suite is development data, not independent
held-out accuracy, and lacks an unprotected control. The existing independent
test set remains unchanged and is not used to tune detection rules.

The outbox tests now also exercise SQLite capacity exhaustion and five backlog
reopens. SQLite's page limit models a full database, not every filesystem failure.
Failed enqueue transactions roll back; events rejected during full storage cannot
be promised durable. Signed installers still require platform signing identities;
the current deliverable remains a reproducible source archive.
