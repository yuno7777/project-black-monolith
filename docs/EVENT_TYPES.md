# The event vocabulary

Every event the three layers emit, what it means, and what class it belongs
to. The event envelope itself is deliberately open on `event_type` — a new
detection must not need a schema change — so this list, the classification
in the dashboard, and the layers that emit are three things that have to
agree, and `contracts/check_contracts.py` is what makes them agree.

## The three classes

Every event type is in exactly one class.

| Class | What it means |
| --- | --- |
| `detection` | A defence ran and found something. |
| `operational` | The defence could not run, or the thing it watches failed. |
| `lifecycle` | The system reporting that it is alive and what it did. |

The distinction that matters is the second one. `generation_truncated` (the
model provider cut the answer short), `upstream_stream_error` (the provider
broke), `analysis_error` (the shield could not analyse a message and
forwarded it unmodified) and `configuration_invalid` (the shield is
misconfigured) are all warnings — but a warning that means "the defence did
not run" is not a warning that means "the defence found something". Counting
them as attacks makes a run in which nothing was flagged read as a
detection, and that is the number an operator reads first.

Nothing is hidden by classifying an event this way. Every event still
reaches the feed, the severity donut and the incident queue; the class only
decides what a *count* means.

The class says what the event means; the severity decides whether it is
counted as a finding. `tool_malformed` is a `detection`, and it is emitted
at `info` when the tool only broke the spec and was served anyway — that one
is not counted, because nothing was found and nothing was stopped.

## What the console's numbers mean

| Card | What it counts |
| --- | --- |
| Detections | Findings: a `detection` at `warning` or `critical`. Not the warnings plus the criticals. |
| Open incidents | Ledger rows nobody has triaged. |
| Critical | Every event at `critical` severity, of any class. A critical that means the defence could not run — a baseline that would not persist, a configuration that was invalid — is critical too. |
| Avg end-to-end latency | The mean of `details.detection_latency_ms`, which includes the wrapped operation, not only the detector. |

The session report (`/api/sessions/<id>`) counts the same way and adds
**blocks**: a finding that actually stopped something. The gap between
detections and blocks is the interesting number — a defence that detects a
lot and blocks nothing is a defence the agent walks straight through.

## The vocabulary

### Detections

| Event type | Class | Layer | Severity | What it means |
| --- | --- | --- | --- | --- |
| `corpus_poison_quarantine` | detection | Memory layer (`vector-anchor`) | critical | A document tripped the poison detector and was quarantined; the next-best clean result was served in its place. |
| `pii_redacted` | detection | Reasoning layer (`trace-audit`) | warning | The answer carried PII or a credential; it was redacted before the answer was forwarded. |
| `reasoning_divergence_terminate` | detection | Reasoning layer (`trace-audit`) | critical | The answer's token distribution diverged from the baseline past the threshold, and the stream was terminated with a refusal. |
| `schema_mismatch` | detection | Tool layer (`mcp-shield`) | critical | A tool's schema no longer matches the baseline the shield registered for it. |
| `secret_boundary_denial` | detection | Tool layer (`mcp-shield`) | critical | The secret boundary refused an operation by policy, so the agent never held the credential. |
| `session_quarantined` | detection | All three layers | critical | The session was quarantined. |
| `suspicious_catalog_entry` | detection | Tool layer (`mcp-shield`) | warning | A `tools/list` entry matched one of the sanitizer's suspicious patterns. |
| `suspicious_description` | detection | Tool layer (`mcp-shield`) | warning | A tool's description, or a secret boundary response body, matched a hidden-instruction pattern. |
| `suspicious_error_payload` | detection | Tool layer (`mcp-shield`) | critical | An error payload returned by an MCP server matched a suspicious pattern. |
| `suspicious_tool_output` | detection | Tool layer (`mcp-shield`) | critical | A tool's output matched a suspicious pattern. |
| `tool_call_argument_flagged` | detection | Tool layer (`mcp-shield`) | warning, critical | The DLP scanner flagged a tool call's arguments. Critical when the finding was one the shield blocks. |
| `tool_malformed` | detection | Tool layer (`mcp-shield`) | warning, info | A tool entry could not be parsed. Warning when the shield withheld it, info when it only broke the spec and was served anyway. |
| `tool_pending_approval` | detection | Tool layer (`mcp-shield`) | warning | A tool call is being held for an operator's approval. |
| `tool_revoked` | detection | Tool layer (`mcp-shield`) | warning | A revoked tool was called. |

### Operational failures

| Event type | Class | Layer | Severity | What it means |
| --- | --- | --- | --- | --- |
| `analysis_error` | operational | Tool layer (`mcp-shield`) | warning | The shield could not analyse a message and forwarded it unmodified. |
| `baseline_lock_failed` | operational | Tool layer (`mcp-shield`) | critical | The shield could not take the baseline's lock, so it did not read, rewrite or register the baseline. |
| `baseline_missing` | operational | Reasoning layer (`trace-audit`) | warning | The divergence baseline file is absent, so the divergence gate is off. |
| `baseline_persist_failed` | operational | Tool layer (`mcp-shield`) | critical | The shield could not persist the baseline it had just computed. |
| `baseline_reload_failed` | operational | Tool layer (`mcp-shield`) | critical | The shield could not reload the trusted baseline. |
| `configuration_invalid` | operational | Tool layer (`mcp-shield`) | warning | A configuration value was invalid. The shield refuses to start rather than run with a setting it did not understand. |
| `generation_truncated` | operational | Reasoning layer (`trace-audit`) | warning | The model provider ended the answer before `message_stop`. |
| `secret_operation_aborted` | operational | Tool layer (`mcp-shield`) | warning | A secret operation was allowed by policy but not executed. |
| `secret_operation_failed` | operational | Tool layer (`mcp-shield`) | warning | A secret operation was allowed by policy and failed at execution. |
| `upstream_stream_error` | operational | Reasoning layer (`trace-audit`) | warning | The model provider's stream broke. |
| `upstream_transport_refused` | operational | Reasoning layer (`trace-audit`) | warning | The configured model upstream is not a trusted transport, so the model credential was not forwarded and the request was refused instead. |

### Lifecycle

| Event type | Class | Layer | Severity | What it means |
| --- | --- | --- | --- | --- |
| `baseline_registered` | lifecycle | Tool layer (`mcp-shield`) | info | The shield registered a tool's baseline. |
| `baseline_reloaded` | lifecycle | Reasoning layer (`trace-audit`) | info | The reasoning layer reloaded its divergence baseline. |
| `divergence_disabled` | lifecycle | Reasoning layer (`trace-audit`) | info | The divergence gate was turned off, with the reason recorded. |
| `generation_completed` | lifecycle | Reasoning layer (`trace-audit`) | info | The reasoning layer finished an answer. |
| `retrieval` | lifecycle | Memory layer (`vector-anchor`) | info | The memory layer served a retrieval. |
| `secret_operation_executed` | lifecycle | Tool layer (`mcp-shield`) | info | The secret boundary allowed and executed a secret operation. |
| `service_start` | lifecycle | Memory layer, reasoning layer | info | A layer started. |
| `service_stop` | lifecycle | Memory layer, reasoning layer | info | A layer stopped. |
| `tools_list_changed` | lifecycle | Tool layer (`mcp-shield`) | info | A server's `tools/list` differs from the one the shield saw before. |

## Adding an event type

Three places, and the build fails if any of them is missed:

1. **Emit it** from the layer that detects it. The type is a literal at the
   emission site, so the check can see it.
2. **Classify it** in `dashboard/lib/event-classification.ts`, in the
   `EVENT_CLASSES` list. An unclassified type is a finding the console does
   not count.
3. **Document it** in the table above.

`contracts/check_contracts.py` scans the layers' sources and fails when a
layer emits a type that is not classified, when an emission site does not
name its type literally, when a classified type is not documented here, and
when a documented type is given a different class here than in the code.

The check enforces the direction that matters — nothing may be emitted that
has not been classified — and not the reverse, so a type can be classified
before the layer that emits it ships.
