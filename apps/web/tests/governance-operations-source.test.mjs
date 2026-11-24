import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/components/command-center/governance-operations.tsx", import.meta.url),
  "utf8",
);

test("operations renders evidence-backed trend, surface matrix, and priority queue", () => {
  for (const label of [
    "Observed interventions",
    "Coverage by surface",
    "Priority queue",
    "Deployment recommendation",
    "Recent activity",
  ]) assert.match(source, new RegExp(label));
  assert.match(source, /AreaChart/);
  assert.match(source, /model\.interventions/);
  assert.match(source, /model\.surfaces/);
  assert.match(source, /priorityActions/);
});

test("surface posture and missing data remain explicit", () => {
  for (const label of ["Inline verified", "Monitor-only", "Not covered", "Unknown"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /No observed interventions/);
  assert.match(source, /No verified deployment surfaces/);
  assert.match(source, /href=\{row\.drilldown\}/);
  assert.match(source, /href=\{action\.href\}/);
});
