import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/components/command-center/governance-storyline.tsx", import.meta.url),
  "utf8",
);

test("storyline renders the approved governance lifecycle in order", () => {
  const labels = ["Discover", "Protect", "Validate", "Prove"];
  let cursor = -1;
  for (const label of labels) {
    const next = source.indexOf(`title=\"${label}\"`, cursor + 1);
    assert.ok(next > cursor, `${label} is missing or out of order`);
    cursor = next;
  }
});

test("storyline uses real chart components and exposes readable summaries", () => {
  assert.match(source, /PieChart/);
  assert.match(source, /BarChart/);
  assert.match(source, /RadarChart/);
  assert.match(source, /aria-label=/);
  assert.match(source, /role="img"/);
  assert.match(source, /Observed estate/);
  assert.match(source, /Inline verified/);
  assert.match(source, /Executed simulations/);
  assert.match(source, /Evidence-linked/);
});

test("storyline is conservative about unknown estate and simulations", () => {
  assert.match(source, /Unknown beyond observed/);
  assert.match(source, /No verified estate denominator/);
  assert.match(source, /No executed simulations/);
  assert.match(source, /model\.executedRuns > 0 && model\.profile\.length >= 3/);
  assert.doesNotMatch(source, /Control Coverage Score|Estate protected|Fully governed/);
});
