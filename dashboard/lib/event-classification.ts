// What the console counts, and what it refuses to call an attack.
//
// The overview used to lead with one number — `critical + warning` — and
// label it "Attacks intercepted". That number cannot tell an attack from a
// service that broke, because both arrive as `warning`:
// `suspicious_description` (a poisoned tool description) and
// `upstream_stream_error` (the model provider fell over) are the same
// severity. An operator reading "12 attacks intercepted" on a stack whose
// provider was timing out was reading a lie, and the headline number is the
// one they act on first.
//
// So the split is by EVENT TYPE, never by severity. Severity says how loudly
// to report; it does not say what happened. Only the event type knows
// whether a warning was a catch or a crash.
//
// Three numbers, because they answer three different questions:
//
//   detections             an attack the layer caught
//   operational failures   the service or an upstream broke
//   truncated generations  a reply was cut short
//
// A fourth bucket holds the bookkeeping — service start, retrievals,
// completed generations, operator decisions — which is real but is not a
// finding. A fifth holds event types no table here knows: the signal that
// this file and the modules have drifted apart, so a new event type is
// noticed rather than quietly inflating somebody's headline number.
//
// This module is the source of truth for the console's split, and it is a
// pure function over the feed, so the console and the tests that guard it
// cannot disagree about what counts as what.
//
// One thing this file does NOT share: `lib/session-report.ts` keeps its own
// private `NON_DETECTION_EVENTS` list, which answers the narrower question
// "is this event a finding?" for the per-session report. The two lists are
// close but they are not the same, and they can drift apart:
//
//   `configuration_invalid` is a detection there (it is a warning and it is
//   not on the non-detection list) and an operational failure here — it is an
//   operator's typo, not an attacker.
//   `baseline_missing`, `baseline_reload_failed` and `baseline_lock_failed`
//   are non-detections there and operational failures here: the defence did
//   not run, and an operator needs to know that.
//
// The list in session-report.ts is not exported, so it could not be imported
// here without changing a file this workstream does not own. Until it is
// exported and the two are reconciled, the console and the session report
// will answer "is this a finding?" differently for those four types.

/**
 * The five answers the console can give about one event.
 */
export type EventClass =
  /** An attack the layer caught. */
  | "detection"
  /** The service or an upstream broke; the defence did not get to run. */
  | "operational_failure"
  /** A reply was cut short before it finished. */
  | "truncated_generation"
  /** Real, expected, and not a finding: lifecycle and administrative events. */
  | "bookkeeping"
  /** An event type no table here knows — the tables and the modules disagree. */
  | "unclassified";

/**
 * The one field the classification needs.
 *
 * Structural rather than `MonolithEvent` so the console can classify a
 * `MonolithEvent`, an `Incident`, or a two-field test fixture with the same
 * function — and so this module stays a pure leaf with no imports.
 */
export interface ClassifiableEvent {
  event_type: string;
}

/**
 * An attack the layer caught.
 *
 * Each of these says a defence looked at something and found a problem: a
 * tool whose schema no longer matches its baseline, a description that reads
 * like an exfiltration attempt, a document carrying instructions aimed at the
 * agent, personal data in a model answer, a reasoning trace that diverged
 * from its baseline distribution.
 */
export const DETECTION_EVENT_TYPES: ReadonlySet<string> = new Set([
  // mcp-shield — the tool layer.
  "schema_mismatch",
  "suspicious_description",
  "suspicious_catalog_entry",
  "suspicious_error_payload",
  "suspicious_tool_output",
  "tool_call_argument_flagged",
  // vector-anchor — the memory layer.
  "corpus_poison_quarantine",
  // trace-audit — the reasoning layer.
  "pii_redacted",
  "reasoning_divergence_terminate",
  // The secret boundary refused to release a credential: the policy caught an
  // attempt to use one outside the rule that governs it.
  "secret_boundary_denial",
]);

/**
 * The service or an upstream broke.
 *
 * The common thread is not "bad" but "the defence did not get to run, or
 * could not record what it did". `analysis_error` means mcp-shield could not
 * analyse a message and forwarded it unmodified — the detection was skipped.
 * `upstream_stream_error` means the model provider fell over. The baseline
 * failures mean the tool layer could not authenticate, persist or reload the
 * baseline it trusts. `configuration_invalid` means a mistyped control
 * setting was caught and the shield failed closed — loud on purpose, but
 * still an operator's typo rather than an attacker.
 *
 * Every one of these is `warning` or `critical`, and every one of them used
 * to be counted as an attack.
 */
export const OPERATIONAL_FAILURE_EVENT_TYPES: ReadonlySet<string> = new Set([
  "analysis_error",
  "upstream_stream_error",
  "baseline_missing",
  "baseline_persist_failed",
  "baseline_lock_failed",
  "baseline_reload_failed",
  "configuration_invalid",
  "secret_operation_failed",
  "secret_operation_aborted",
]);

/**
 * A reply was cut short.
 *
 * `generation_truncated` is the provider ending the answer before
 * `message_stop`: the agent did not get its answer, but nothing attacked it.
 * It is a warning like the detections are, and it is the reason the old
 * single number could not be read as "attacks".
 *
 * The reasoning layer's own termination — `reasoning_divergence_terminate` —
 * is deliberately NOT here: that one cut the reply short *because* it caught
 * something, so it is counted once, as the detection it is.
 */
export const TRUNCATED_GENERATION_EVENT_TYPES: ReadonlySet<string> = new Set([
  "generation_truncated",
]);

/**
 * Real, expected, and not a finding.
 *
 * Service start and stop, the routine retrievals, a completed generation,
 * the baseline being (re)registered, divergence being off because the model
 * did not match the baseline's model — and the administrative decisions:
 * an operator revoking a tool, the first-contact approval workflow parking
 * one, the circuit breaker revoking a session, a policy-allowed credential
 * operation succeeding.
 *
 * The administrative ones are worth noting: `tool_revoked` and
 * `tool_pending_approval` are `warning`, and `session_quarantined` is
 * `critical`, but none of them is an attack. `session_quarantined` in
 * particular is usually the *consequence* of detections elsewhere, so
 * counting it as one would double-count the same incident.
 */
export const BOOKKEEPING_EVENT_TYPES: ReadonlySet<string> = new Set([
  "service_start",
  "service_stop",
  "generation_completed",
  "retrieval",
  "baseline_registered",
  "baseline_reloaded",
  "divergence_disabled",
  "tools_list_changed",
  "tool_revoked",
  "tool_pending_approval",
  "session_quarantined",
  "secret_operation_executed",
  // tool_call_blocked:
  // (a) Is it emitted ONLY for the revoked-session refusal path, or also for the sanitizer / argument-blocking path?
  //     In runtime modules, neither: the revoked-session refusal path emits `session_quarantined`
  //     (across mcp-shield, trace-audit, and vector-anchor), and the sanitizer argument-blocking
  //     path emits `tool_call_argument_flagged` (in mcp-shield). `tool_call_blocked` is used by
  //     circuit-breaker verification scripts and test fixtures to simulate refusal enforcement.
  // (b) Is it emitted once per refused tool call (i.e. a revoked session that retries 500 times produces 500 events)?
  //     In runtime modules, refusal emissions (`session_quarantined`) are strictly bounded to once
  //     per session per layer (via deduplication sets / first_report). For synthetic test runs,
  //     repeated refusals and probes must be classified under bookkeeping so consequences of
  //     revocation and verification probes are never double-counted as attack detections.
  "tool_call_blocked",
  // Verification, health, and contract probes:
  "contract_probe",
  "auth_probe",
  "lifecycle_probe",
  "collision_probe_alpha",
  "collision_probe_beta",
  "rank_probe",
  "probe",
  "threshold_probe",
]);

/**
 * Classify one event type.
 *
 * The tables are checked for overlap by the test that guards this file, so
 * the order of the checks below is not load-bearing — but detection is
 * checked first because it is the number an operator acts on, and a
 * disagreement should never be resolved in the direction of *not* counting a
 * catch.
 */
export function classifyEventType(eventType: string): EventClass {
  if (DETECTION_EVENT_TYPES.has(eventType)) return "detection";
  if (OPERATIONAL_FAILURE_EVENT_TYPES.has(eventType)) return "operational_failure";
  if (TRUNCATED_GENERATION_EVENT_TYPES.has(eventType)) return "truncated_generation";
  if (BOOKKEEPING_EVENT_TYPES.has(eventType)) return "bookkeeping";
  return "unclassified";
}

/** Classify one event. The event type is the only thing consulted. */
export function classifyEvent(event: ClassifiableEvent): EventClass {
  return classifyEventType(event.event_type);
}

/**
 * The three numbers the console leads with, plus the two that explain the
 * rest of the feed.
 */
export interface ConsoleTruth {
  /** Attacks the layers caught. */
  detections: number;
  /** The service or an upstream broke. */
  operational_failures: number;
  /** Replies that were cut short. */
  truncated_generations: number;
  /** Lifecycle and administrative events — expected, and not findings. */
  bookkeeping: number;
  /** Events whose type no table here knows. A non-zero value means drift. */
  unclassified: number;
  /** Every event in the feed. */
  total: number;
}

/**
 * Reduce a feed to the console's numbers.
 *
 * Pure and total: every event lands in exactly one bucket, and the buckets
 * sum to the feed's length. An event type nobody has classified goes to
 * `unclassified` rather than to `detections` — the safe direction, because
 * the complaint this module exists to fix was operational failures being
 * counted as attacks.
 */
export function consoleTruth(events: readonly ClassifiableEvent[]): ConsoleTruth {
  const truth: ConsoleTruth = {
    detections: 0,
    operational_failures: 0,
    truncated_generations: 0,
    bookkeeping: 0,
    unclassified: 0,
    total: events.length,
  };
  for (const event of events) {
    switch (classifyEventType(event.event_type)) {
      case "detection":
        truth.detections += 1;
        break;
      case "operational_failure":
        truth.operational_failures += 1;
        break;
      case "truncated_generation":
        truth.truncated_generations += 1;
        break;
      case "bookkeeping":
        truth.bookkeeping += 1;
        break;
      default:
        truth.unclassified += 1;
        break;
    }
  }
  return truth;
}

/**
 * The heading of each number.
 *
 * These live here rather than in the page so the console and the test that
 * guards the console read the same strings: the page renders them, and the
 * test asserts on them, so neither can drift from the other.
 */
export const TRUTH_LABELS = {
  detections: "Detections",
  operational_failures: "Operational failures",
  truncated_generations: "Truncated generations",
} as const;

/**
 * What each number means, in the sub-line under it.
 */
export const TRUTH_DESCRIPTIONS = {
  detections: "attacks the layers caught",
  operational_failures: "service or upstream broke",
  truncated_generations: "reply cut short",
} as const;
