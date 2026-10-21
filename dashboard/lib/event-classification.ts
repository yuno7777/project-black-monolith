// What counts as a detection.
//
// The console's headline number and the session report both answer "did a
// defence find something", and they have to answer it the same way. When two
// numbers claim the same thing and disagree, an operator has to work out
// which one to believe — and the one that hides a real detection is the one
// that costs.
//
// The rule is by event type, not by outcome, because outcome cannot carry it.
// `generation_truncated` and `reasoning_divergence_terminate` both end a
// stream, both carry the outcome "terminated", and they mean opposite
// things: one is the model provider cutting an answer short, the other is
// the reasoning layer refusing to answer at all. MCP-Shield goes further and
// derives the outcome from the severity when a call carries no explicit
// action, so outcome is not a stable input to a classification.
//
// Three classes:
//
//   detection     a defence ran and found something
//   operational   the defence could not run, or the thing it watches failed
//   lifecycle     the system reporting that it is alive and what it did
//
// The distinction that matters is the second one. `generation_truncated` (the
// provider cut the answer short), `upstream_stream_error` (the provider
// broke), `analysis_error` (the shield could not analyse a message and
// forwarded it unmodified) and `configuration_invalid` (the shield is
// misconfigured) are all warnings — but a warning that means "the defence did
// not run" is not a warning that means "the defence found something".
// Counting them as attacks makes a run in which nothing was flagged read as
// a detection, and that is the number an operator reads first.
//
// Nothing is hidden by classifying an event this way. Every event still
// reaches the feed, the severity donut and the incident queue; the
// classification only decides what a *count* means.
//
// An event type that is not listed here is "unknown", and an unknown event is
// not counted as a detection. `contracts/check_contracts.py` fails the build
// when a layer emits a type this file does not list, so "unknown" can only
// mean a dashboard older than the layer that emitted the event.

import type { Severity } from "@/lib/types";

/** The three classes an emitted event can fall into. */
export type EventClass = "detection" | "operational" | "lifecycle";

/** A class, plus the one that means "this file does not know the type". */
export type EventClassification = EventClass | "unknown";

/** The minimum an event has to carry to be classified. */
export interface ClassifiableEvent {
  event_type?: string | null;
  severity?: Severity | string | null;
}

/**
 * Every event type the three layers can emit, and what it means.
 *
 * This is the contract, and three things have to agree about it: the code
 * that counts, the documentation that names it (`docs/EVENT_TYPES.md`), and
 * the check that fails when a layer emits a type nobody classified
 * (`contracts/check_contracts.py`). Adding a detection means adding it here
 * as well, or the console will not count it.
 *
 * The list is read by that check, so the shape matters: one
 * `"event_type": "class",` per line, and nothing else in the object.
 */
export const EVENT_CLASSES: Record<string, EventClass> = {
  // --- detections: a defence ran and found something ----------------------

  // The memory layer quarantined a document that tripped the poison
  // detector. The next-best clean result is served in its place.
  "corpus_poison_quarantine": "detection",
  // The reasoning layer found PII or a credential in the answer and
  // redacted it before the answer was forwarded.
  "pii_redacted": "detection",
  // The reasoning layer's rolling KL divergence breached its baseline and
  // the stream was terminated with a refusal.
  "reasoning_divergence_terminate": "detection",
  // A tool's schema no longer matches the baseline the shield registered
  // for it — the rug pull the tool layer exists to catch.
  "schema_mismatch": "detection",
  // The secret boundary refused an operation by policy. The agent never
  // held the credential it asked for.
  "secret_boundary_denial": "detection",
  // A session was quarantined, by any of the three layers.
  "session_quarantined": "detection",
  // A tools/list entry matched one of the sanitizer's suspicious patterns.
  "suspicious_catalog_entry": "detection",
  // A tool's description — or a secret boundary response body — matched a
  // hidden-instruction pattern.
  "suspicious_description": "detection",
  // An error payload returned by an MCP server matched a suspicious pattern.
  "suspicious_error_payload": "detection",
  // A tool's output matched a suspicious pattern.
  "suspicious_tool_output": "detection",
  // The DLP / exfiltration scanner flagged a tool call's arguments. The
  // severity is warning or critical depending on whether the finding was
  // one the shield blocks.
  "tool_call_argument_flagged": "detection",
  // A tool entry could not be parsed. Warning when the shield withheld it
  // (the agent never saw it), info when it only broke the spec and was
  // served anyway — so the severity decides, not the type.
  "tool_malformed": "detection",
  // A tool call is being held for an operator's approval.
  "tool_pending_approval": "detection",
  // A tool that had been revoked was called.
  "tool_revoked": "detection",

  // --- operational: the defence could not run, or its subject failed -----

  // The shield could not analyse a message and forwarded it unmodified.
  "analysis_error": "operational",
  // The shield could not take the baseline's lock, so it did not read,
  // rewrite or register the baseline.
  "baseline_lock_failed": "operational",
  // The reasoning layer's divergence baseline file is absent, so the
  // divergence gate is off.
  "baseline_missing": "operational",
  // The shield could not persist the baseline it had just computed.
  "baseline_persist_failed": "operational",
  // The shield could not reload the trusted baseline.
  "baseline_reload_failed": "operational",
  // A configuration value was invalid. The shield refuses to start rather
  // than run with a setting it did not understand.
  "configuration_invalid": "operational",
  // The model provider ended the answer before message_stop.
  "generation_truncated": "operational",
  // A secret operation was allowed by policy but not executed.
  "secret_operation_aborted": "operational",
  // A secret operation was allowed by policy and failed at execution.
  "secret_operation_failed": "operational",
  // The model provider's stream broke.
  "upstream_stream_error": "operational",
  // The configured model upstream is not a trusted transport, so the model
  // credential was not forwarded. The request was refused instead.
  "upstream_transport_refused": "operational",

  // --- lifecycle: the system saying what it did --------------------------

  // The shield registered a tool's baseline.
  "baseline_registered": "lifecycle",
  // The reasoning layer reloaded its divergence baseline.
  "baseline_reloaded": "lifecycle",
  // The divergence gate was turned off, with the reason recorded.
  "divergence_disabled": "lifecycle",
  // The reasoning layer finished an answer.
  "generation_completed": "lifecycle",
  // The memory layer served a retrieval.
  "retrieval": "lifecycle",
  // A layer started.
  "service_start": "lifecycle",
  // A layer stopped.
  "service_stop": "lifecycle",
  // The secret boundary allowed and executed a secret operation.
  "secret_operation_executed": "lifecycle",
  // A server's tools/list differs from the one the shield saw before.
  "tools_list_changed": "lifecycle",
};

/**
 * The class of an event, or "unknown" for a type this file does not list.
 */
export function classifyEvent(event: ClassifiableEvent): EventClassification {
  const type = event.event_type;
  if (!type) return "unknown";
  return EVENT_CLASSES[type] ?? "unknown";
}

/**
 * Whether an event is a finding: something a defence looked for and found.
 *
 * Severity gates the answer, because one type is emitted at two severities
 * on purpose. `tool_malformed` is a warning when the shield withheld the
 * tool — the agent never saw it, so it is a finding — and info when the tool
 * only broke the spec and was served anyway, which is not.
 */
export function isDetectionEvent(event: ClassifiableEvent): boolean {
  if (classifyEvent(event) !== "detection") return false;
  return event.severity === "warning" || event.severity === "critical";
}

/**
 * How many of these events are findings.
 *
 * This is the number the console's headline card and the session report both
 * mean by "detections", and it is deliberately not "the warnings plus the
 * criticals": an operational failure is a warning too, and it is not a
 * finding.
 */
export function countDetections(events: ClassifiableEvent[]): number {
  let detections = 0;
  for (const event of events) {
    if (isDetectionEvent(event)) detections += 1;
  }
  return detections;
}
