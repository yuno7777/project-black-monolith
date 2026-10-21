// What counts as a detection.
//
// The console's headline number and the session report both answer "did a
// defence find something", and they have to answer it the same way. These
// tests pin the rule that answers it, because the rule is where the two
// used to drift apart: the session report excluded the operational
// failures, and the console's headline card counted every warning and every
// critical as an intercepted attack.
//
// No database and no rendered page: the rule is a pure function over the
// events, so it is exercised directly.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  classifyEvent,
  countDetections,
  EVENT_CLASSES,
  isDetectionEvent,
} from "../lib/event-classification";
import type { MonolithEvent, Severity } from "../lib/types";

function event(
  event_type: string,
  severity: Severity,
  module = "mcp-shield",
): MonolithEvent {
  return {
    event_id: randomUUID(),
    schema_version: 2,
    timestamp_ms: 1,
    module,
    event_type,
    severity,
    details: {},
    tenant_id: "tenant-vocab",
  };
}

/**
 * The operational failures — the events that mean a defence could not run,
 * or that the thing it watches broke. Every one of these is a warning or a
 * critical, so every one of them used to be counted as an intercepted
 * attack.
 */
const OPERATIONAL = [
  "generation_truncated",
  "upstream_stream_error",
  "analysis_error",
  "configuration_invalid",
  "baseline_missing",
  "secret_operation_failed",
  "secret_operation_aborted",
  "upstream_transport_refused",
] as const;

/** The findings: a defence ran and found something. */
const DETECTIONS = [
  "schema_mismatch",
  "suspicious_catalog_entry",
  "suspicious_description",
  "suspicious_error_payload",
  "suspicious_tool_output",
  "tool_call_argument_flagged",
  "tool_pending_approval",
  "tool_revoked",
  "secret_boundary_denial",
  "corpus_poison_quarantine",
  "session_quarantined",
  "reasoning_divergence_terminate",
  "pii_redacted",
] as const;

test("an operational failure is not a detection", () => {
  for (const event_type of OPERATIONAL) {
    assert.equal(
      isDetectionEvent(event(event_type, "warning")),
      false,
      `${event_type} is a warning that means the defense did not run, not a finding`,
    );
  }
  // Two of them are critical: the shield could not persist or reload the
  // baseline, so the rug-pull defence was not in force.
  for (const event_type of ["baseline_persist_failed", "baseline_reload_failed", "baseline_lock_failed"]) {
    assert.equal(
      isDetectionEvent(event(event_type, "critical")),
      false,
      `${event_type} is a critical that means the defense could not run, not a finding`,
    );
  }
});

test("a finding is a detection", () => {
  for (const event_type of DETECTIONS) {
    assert.equal(
      isDetectionEvent(event(event_type, "critical")),
      true,
      `${event_type} is something a defense found`,
    );
    assert.equal(
      isDetectionEvent(event(event_type, "warning")),
      true,
      `${event_type} is something a defense found`,
    );
  }
});

test("the severity decides, not the type", () => {
  // A tool the shield could not vouch for: withheld, so the agent never saw
  // it, so it is a finding. The same tool only breaking the spec was still
  // checked and still served, so it is not.
  assert.equal(isDetectionEvent(event("tool_malformed", "warning")), true);
  assert.equal(isDetectionEvent(event("tool_malformed", "info")), false);
});

test("the lifecycle is not a detection", () => {
  for (const event_type of [
    "service_start",
    "service_stop",
    "retrieval",
    "generation_completed",
    "baseline_registered",
    "baseline_reloaded",
    "divergence_disabled",
    "tools_list_changed",
    "secret_operation_executed",
  ]) {
    assert.equal(classifyEvent(event(event_type, "info")), "lifecycle");
    assert.equal(isDetectionEvent(event(event_type, "info")), false);
  }
});

test("an event type nobody classified is not a detection", () => {
  // A dashboard older than the layer that emitted the event. It is not
  // counted as a finding, because the dashboard cannot know that it is one;
  // `contracts/check_contracts.py` is what stops the two from drifting.
  assert.equal(classifyEvent(event("a_type_from_the_future", "critical")), "unknown");
  assert.equal(isDetectionEvent(event("a_type_from_the_future", "critical")), false);
});

test("the console's headline number counts findings, not severities", () => {
  // The feed of a run in which one thing was found and the provider fell
  // over twice.
  const feed: MonolithEvent[] = [
    event("schema_mismatch", "critical"),
    event("generation_truncated", "warning", "trace-audit"),
    event("upstream_stream_error", "warning", "trace-audit"),
    event("retrieval", "info", "vector-anchor"),
    event("service_start", "info", "trace-audit"),
  ];

  // One finding. The old count — every warning plus every critical — would
  // have said three, which is the number the overview showed for a run in
  // which exactly one thing was found.
  assert.equal(countDetections(feed), 1);
  // And the severities the old count summed are still there to be seen.
  const warnings = feed.filter((e) => e.severity === "warning").length;
  const criticals = feed.filter((e) => e.severity === "critical").length;
  assert.equal(warnings + criticals, 3);
});

test("the session report and the console count the same thing", async () => {
  const { summarizeSession } = await import("../lib/session-report");

  const incidents = [
    { ...event("schema_mismatch", "critical"), outcome: "rewritten" },
    { ...event("generation_truncated", "warning", "trace-audit"), outcome: "terminated" },
    { ...event("analysis_error", "warning"), outcome: "degraded" },
  ];

  const summary = summarizeSession(incidents);
  assert.equal(summary.detections, countDetections(incidents));
  assert.equal(summary.detections, 1);
  // Two things stopped the agent: the poisoned schema was rewritten and the
  // truncated answer never arrived. Only one of them was a finding — which is
  // the whole point of the two numbers being separate.
  assert.equal(summary.blocks, 2);
});

test("every classified event type is classified as one of the three classes", () => {
  const classes = new Set(Object.values(EVENT_CLASSES));
  for (const value of classes) {
    assert.ok(
      value === "detection" || value === "operational" || value === "lifecycle",
      `${value} is not one of the three classes`,
    );
  }
  // The lists above are the vocabulary, and the vocabulary is what the
  // layers emit. A type that is classified as a finding must be one of the
  // findings the layers raise, and a type that is not a finding must not be
  // one of them.
  for (const event_type of DETECTIONS) {
    assert.equal(EVENT_CLASSES[event_type], "detection");
  }
  for (const event_type of OPERATIONAL) {
    assert.equal(EVENT_CLASSES[event_type], "operational");
  }
});
