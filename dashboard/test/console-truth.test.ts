// The console's three numbers, and the reason there are three of them.
//
// The overview used to lead with one number — `critical + warning` — and call
// it "Attacks intercepted". An operational failure and a truncated generation
// are both warnings, so both were counted as attacks, and an operator could
// not tell a catch from a crash. These tests hold that split in place.
//
// Same harness as onboarding.test.ts: node:test, node:assert/strict, run with
// `npx tsx --test test/console-truth.test.ts`. No database and no browser —
// the classification is a pure function, and the overview is checked by
// reading its source, so what is asserted here is exactly what it renders.

import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  BOOKKEEPING_EVENT_TYPES,
  DETECTION_EVENT_TYPES,
  OPERATIONAL_FAILURE_EVENT_TYPES,
  TRUNCATED_GENERATION_EVENT_TYPES,
  TRUTH_DESCRIPTIONS,
  TRUTH_LABELS,
  classifyEvent,
  classifyEventType,
  consoleTruth,
} from "../lib/event-classification";

type Severity = "info" | "warning" | "critical";

/**
 * One event of the feed.
 *
 * Only the event type and the severity are set, because those are the only
 * two things a reader could reasonably have classified on: the event type is
 * the axis the split runs on, and the severity is the axis it must not.
 */
function event(event_type: string, severity: Severity = "warning") {
  return { event_type, severity };
}

/**
 * The feed the acceptance criterion describes: one detection, one
 * operational failure, one truncated generation — and the bookkeeping every
 * real feed also carries.
 */
const FEED = [
  event("schema_mismatch", "warning"), // an attack the tool layer caught
  event("upstream_stream_error", "warning"), // the model provider broke
  event("generation_truncated", "warning"), // the provider cut the reply short
  event("retrieval", "info"), // bookkeeping
  event("generation_completed", "info"), // bookkeeping
];

test("one detection, one operational failure and one truncation are three numbers", () => {
  const truth = consoleTruth(FEED);

  // Three separately reported counts, each of the one event that belongs to
  // it — not one number that swallowed all three.
  assert.equal(truth.detections, 1);
  assert.equal(truth.operational_failures, 1);
  assert.equal(truth.truncated_generations, 1);

  // The old headline counted all three: every one of them is a warning. The
  // whole point of the split is that this number is no longer the number on
  // screen.
  const oldHeadline = FEED.filter(
    (e) => e.severity === "warning" || e.severity === "critical",
  ).length;
  assert.equal(oldHeadline, 3);
  assert.notEqual(truth.detections, oldHeadline);

  // And the counts are independent: a feed with two catches and one failure
  // and one truncation reports 2, 1 and 1 — two of the three figures differ,
  // which is only possible if the counts are not one number split three ways.
  const uneven = consoleTruth([
    event("schema_mismatch"),
    event("pii_redacted"),
    event("upstream_stream_error"),
    event("generation_truncated"),
  ]);
  assert.equal(uneven.detections, 2);
  assert.equal(uneven.operational_failures, 1);
  assert.equal(uneven.truncated_generations, 1);
  assert.equal(new Set([uneven.detections, uneven.operational_failures, uneven.truncated_generations]).size, 2);
});

test("severity is not the axis the split runs on", () => {
  const types = ["schema_mismatch", "upstream_stream_error", "generation_truncated"];
  for (const severity of ["info", "warning", "critical"] as const) {
    const truth = consoleTruth(types.map((type) => event(type, severity)));
    assert.deepEqual(
      {
        detections: truth.detections,
        operational_failures: truth.operational_failures,
        truncated_generations: truth.truncated_generations,
      },
      { detections: 1, operational_failures: 1, truncated_generations: 1 },
      `severity ${severity} must not move an event between classes`,
    );
  }

  // A critical operational failure is still a failure, not an attack.
  assert.equal(classifyEventType("baseline_persist_failed"), "operational_failure");
  assert.equal(classifyEventType("configuration_invalid"), "operational_failure");
  // And the reasoning layer's own termination is counted once, as the
  // detection it is — not again as a truncation.
  assert.equal(classifyEventType("reasoning_divergence_terminate"), "detection");
});

test("the labels say which number is which", () => {
  assert.match(TRUTH_LABELS.detections, /detection/i);
  assert.match(TRUTH_LABELS.operational_failures, /operational/i);
  assert.match(TRUTH_LABELS.operational_failures, /failure/i);
  assert.match(TRUTH_LABELS.truncated_generations, /truncat/i);

  const labels = Object.values(TRUTH_LABELS);
  assert.equal(new Set(labels).size, labels.length, "the three labels must be distinguishable");

  // The sub-line under each number says what it counted.
  assert.match(TRUTH_DESCRIPTIONS.detections, /attack|caught/i);
  assert.match(TRUTH_DESCRIPTIONS.operational_failures, /broke|upstream|service/i);
  assert.match(TRUTH_DESCRIPTIONS.truncated_generations, /cut short|truncat/i);
});

test("no event type is in two classes at once", () => {
  const tables: Array<[string, ReadonlySet<string>]> = [
    ["detection", DETECTION_EVENT_TYPES],
    ["operational_failure", OPERATIONAL_FAILURE_EVENT_TYPES],
    ["truncated_generation", TRUNCATED_GENERATION_EVENT_TYPES],
    ["bookkeeping", BOOKKEEPING_EVENT_TYPES],
  ];
  const owner = new Map<string, string>();
  for (const [name, table] of tables) {
    for (const type of table) {
      assert.equal(
        owner.has(type),
        false,
        `${type} is in both ${owner.get(type)} and ${name}`,
      );
      owner.set(type, name);
    }
  }
});

test("every event type the modules emit is classified", () => {
  const vocabulary = [
    // mcp-shield — the tool layer.
    "schema_mismatch",
    "suspicious_description",
    "suspicious_catalog_entry",
    "suspicious_error_payload",
    "suspicious_tool_output",
    "tool_call_argument_flagged",
    "tool_revoked",
    "tool_pending_approval",
    "analysis_error",
    "configuration_invalid",
    "baseline_registered",
    "baseline_persist_failed",
    "baseline_lock_failed",
    "baseline_reload_failed",
    "tools_list_changed",
    // vector-anchor — the memory layer.
    "service_start",
    "service_stop",
    "retrieval",
    "corpus_poison_quarantine",
    // trace-audit — the reasoning layer.
    "baseline_missing",
    "baseline_reloaded",
    "divergence_disabled",
    "generation_completed",
    "generation_truncated",
    "upstream_stream_error",
    "pii_redacted",
    "reasoning_divergence_terminate",
    // The secret boundary.
    "secret_operation_executed",
    "secret_operation_failed",
    "secret_operation_aborted",
    "secret_boundary_denial",
    // The cross-layer circuit breaker, from every layer.
    "session_quarantined",
    // Circuit breaker verification and test fixtures.
    "tool_call_blocked",
    // Verification, health, and contract probes.
    "contract_probe",
    "auth_probe",
    "lifecycle_probe",
    "collision_probe_alpha",
    "collision_probe_beta",
    "rank_probe",
    "probe",
    "threshold_probe",
  ];
  for (const type of vocabulary) {
    assert.notEqual(
      classifyEventType(type),
      "unclassified",
      `${type} is emitted by a module but classified by nobody`,
    );
  }
});

test("an event type nobody classified is not counted as an attack", () => {
  const truth = consoleTruth([event("schema_mismatch"), event("a_type_from_the_future")]);
  assert.equal(truth.detections, 1);
  assert.equal(truth.unclassified, 1);
  assert.equal(truth.total, 2);
});

test("the buckets account for every event in the feed", () => {
  const truth = consoleTruth(FEED);
  assert.equal(
    truth.detections +
      truth.operational_failures +
      truth.truncated_generations +
      truth.bookkeeping +
      truth.unclassified,
    truth.total,
  );
  assert.equal(truth.bookkeeping, 2);
});

test("classifyEvent and classifyEventType agree", () => {
  for (const type of [...DETECTION_EVENT_TYPES, ...BOOKKEEPING_EVENT_TYPES]) {
    assert.equal(classifyEvent({ event_type: type }), classifyEventType(type));
  }
});

const PAGE_SOURCE = readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8");

test("the overview renders the shared labels instead of a copy of them", () => {
  assert.match(PAGE_SOURCE, /from "@\/lib\/event-classification"/);
  for (const key of ["detections", "operational_failures", "truncated_generations"] as const) {
    assert.ok(
      PAGE_SOURCE.includes(`TRUTH_LABELS.${key}`),
      `the overview must render TRUTH_LABELS.${key}`,
    );
  }
  // The old headline is gone. No KPI may claim to be an attack count built
  // from the severity axis.
  assert.doesNotMatch(PAGE_SOURCE, /k:\s*"Attacks intercepted"/);
});

test("no event type emitted by module sources is unclassified", () => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const moduleDirs = [
    join(repoRoot, "mcp-shield", "src"),
    join(repoRoot, "trace-audit", "src"),
    join(repoRoot, "vector-anchor", "src"),
    join(repoRoot, "crates", "pbm-secret-boundary", "src"),
  ];

  function getFiles(dir: string, ext: string[]): string[] {
    const results: string[] = [];
    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const full = join(dir, entry);
        const stat = statSync(full);
        if (stat.isDirectory()) {
          results.push(...getFiles(full, ext));
        } else if (ext.some((e) => entry.endsWith(e))) {
          results.push(full);
        }
      }
    } catch {
      // directory might not exist in isolated test context
    }
    return results;
  }

  const emittedTypes = new Set<string>();
  const emitRegex = /(?:emit|emit_traced)\s*\(\s*["']([a-zA-Z0-9_]+)["']/g;

  for (const dir of moduleDirs) {
    const files = getFiles(dir, [".rs", ".py"]);
    for (const file of files) {
      const content = readFileSync(file, "utf8");
      let match;
      while ((match = emitRegex.exec(content)) !== null) {
        const type = match[1];
        // filter out non-event parameters (like variable names or internal helpers)
        if (type && !["event_type", "message"].includes(type)) {
          emittedTypes.add(type);
        }
      }
    }
  }

  assert.ok(emittedTypes.size > 0, "must find emitted types in module sources");
  for (const type of emittedTypes) {
    assert.notEqual(
      classifyEventType(type),
      "unclassified",
      `Event type "${type}" is emitted in module code (${[...moduleDirs].join(", ")}) but remains unclassified`,
    );
  }
});

