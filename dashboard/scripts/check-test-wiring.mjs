// Keep the dashboard's test suite honest about what it actually runs.
//
// The test script names its files explicitly. That is deliberate — the
// command runs under cmd.exe on Windows, which does not expand a glob, so a
// glob would silently match nothing on one platform and everything on
// another. But an explicit list is also a list somebody has to remember to
// update, and the failure is silent: a test file that is not named is never
// run, never fails, and nobody notices. The tests that guarded the live
// ingest contract were in exactly that state for as long as they existed.
//
// This check closes it. Every test file on disk has to be named by the test
// script, every name in the script has to exist on disk, and the files that
// deliberately need a live stack have to be named by a CI workflow instead.

import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const dashboardDir = join(scriptsDir, "..");
const repoDir = join(dashboardDir, "..");
const testDir = join(dashboardDir, "test");

// Test files that cannot run in `npm test` because they need a running
// stack, and are run by a CI job against one instead. A file in this list
// is checked against the workflows below rather than against the test
// script.
const LIVE_STACK_TESTS = ["test/malformed-event.test.mjs"];

const packageJson = JSON.parse(
  await readFile(join(dashboardDir, "package.json"), "utf8"),
);
const testScript = packageJson.scripts?.test ?? "";

const onDisk = (await readdir(testDir))
  .filter((file) => /\.(test\.ts|test\.mjs)$/.test(file))
  .map((file) => `test/${file}`)
  .sort();

const named = new Set();
for (const match of testScript.matchAll(/test\/[\w.-]+/g)) named.add(match[0]);

const problems = [];

for (const file of onDisk) {
  if (LIVE_STACK_TESTS.includes(file)) continue;
  if (!named.has(file)) {
    problems.push(
      `${file} is not in the test script — it would never run. ` +
        `Add it to scripts.test in dashboard/package.json.`,
    );
  }
}

for (const name of named) {
  if (!onDisk.includes(name)) {
    problems.push(
      `the test script names ${name}, which is not in dashboard/test/ — ` +
        `remove the stale entry.`,
    );
  }
}

// A live-stack test is only "wired" if some workflow actually runs it.
const workflowDir = join(repoDir, ".github", "workflows");
const workflows = await readdir(workflowDir);
let workflowText = "";
for (const file of workflows) {
  if (!file.endsWith(".yml") && !file.endsWith(".yaml")) continue;
  workflowText += await readFile(join(workflowDir, file), "utf8");
}
for (const file of LIVE_STACK_TESTS) {
  if (!workflowText.includes(file)) {
    problems.push(
      `${file} needs a live stack, so it is not in the test script — but no ` +
        `workflow runs it either. It is dead code.`,
    );
  }
}

if (problems.length) {
  throw new Error(
    ["The dashboard's test suite is not wired correctly.", ...problems].join("\n"),
  );
}

console.log(
  `[test-wiring] Checked ${onDisk.length - LIVE_STACK_TESTS.length} in-process test ` +
    `file(s) and ${LIVE_STACK_TESTS.length} live-stack test file(s).`,
);
