# Evaluation and protected agent workflow

## Deterministic regression

```text
python evaluation/run_profile.py deterministic
```

This profile is a synthetic regression suite. It does not estimate field accuracy.

## Real models

Install the Python service dependencies, run Ollama, and pull the chosen models
before evaluation. No model is downloaded or silently substituted by the trace
runner. Chroma downloads its default semantic embedding model on first use.

```text
ollama pull llama3.2:1b
ollama pull qwen2.5:0.5b
python evaluation/run_profile.py real --models llama3.2:1b qwen2.5:0.5b
```

`evaluation/held_out.json` separates calibration and held-out prompts and includes
code, multilingual, topic-shift, legitimate tool documentation, injection, and
synthetic secret cases. Reports contain confusion matrices by category, model
identity/digest, generation settings, baseline/data hashes, policy version, and
p95 auditing overhead. Output content is hashed rather than copied to the report.
A labelled attack prompt is not proof that the model actually complied; the
report separately records whether detectable secrets appeared in the raw output
and survived redaction. The dataset is small and authored, so results are
exploratory. No threshold tuning occurs on held-out cases.

The streaming scanner keeps a 256-character look-behind, independent of token
fragment count. Its incomplete/overlong-candidate behavior trades some latency
and false positives on long identifiers for preventing prefix leakage. Arbitrary
encodings and all forms of obfuscation are not covered.

## Protected note agent

Start the native stack using a real model (set `MONOLITH_OLLAMA_MODEL` in `.env`):

```text
python scripts/run_local_demo.py --backend ollama --skip-attacks
```

In another terminal with the same Python environment:

```text
python examples/protected_agent.py "Summarize this project" --note examples/project-note.txt --state-dir .agent-state
```

The agent reads one operator-selected note through the Rust MCP proxy, retrieves
filtered context through VectorAnchor, and sends the grounded prompt through
TraceAudit. It has no shell or arbitrary network tools. Its session ID is printed
for dashboard investigation. The note tool is deliberately read-only and bounded
to 64 KiB. The deterministic mock stack can exercise the same wiring, but its
output is not a real model answer.

Trust baselines persist in `--state-dir`; use a separate directory for each tool
server identity. Initial clean schemas use the project's existing first-contact
policy. For deliberate approval workflows, configure `MCP_SHIELD_FIRST_CONTACT`.

The native three-attack demo also verifies persisted findings and cross-layer
correlation, then runs the example agent. It exits nonzero on missing detections,
missing ledger events, or service failures.

## Reset and recovery

```text
python scripts/reset_demo_state.py
python scripts/reset_demo_state.py --state-dir /path/printed/by/native/demo
```

The first command resets live VectorAnchor frequency/quarantine state using its
admin credential. It keeps the corpus and PostgreSQL ledger. The second inspects
a marked native state directory and explains how to start fresh. Stop the local
runner before removing its retained temporary state. Every new native demo has
isolated MCP, Chroma, and TraceAudit state. Incident deletion is intentionally
separate from demo reset; use the existing retention controls for ledger policy.

Logs remain in the printed native state directory. Failed startup exits nonzero
and stops owned processes. Occupied ports are rejected. Existing services on
those ports are never killed.
