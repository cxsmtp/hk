import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/components/command-center/evidence-river.tsx", import.meta.url),
  "utf8",
);
const css = readFileSync(new URL("../src/app/globals.css", import.meta.url), "utf8");

test("river presents a bounded live chronology with a Now entry point", () => {
  assert.match(source, /Evidence River/);
  assert.match(source, />Now</);
  assert.match(source, />Past</);
  assert.match(source, /events\.slice\(-8\)/);
  assert.match(source, /ReactFlow/);
  assert.match(source, /type: "default"/);
  assert.match(source, /animated: !paused/);
});

test("selection pauses motion while retaining real investigation links", () => {
  assert.match(source, /const \[selectedId, setSelectedId\]/);
  assert.match(source, /const paused = Boolean\(selectedEvent\)/);
  assert.match(source, /Resume flow/);
  assert.match(source, /event\.traceHref/);
  assert.match(source, /event\.evidenceHref/);
  assert.match(source, /event\.findingHref/);
});

test("river distinguishes event types and never adds a Foundry connector", () => {
  for (const label of ["Action", "Alert", "Intervention", "Enforcement", "Proof"]) {
    assert.match(source, new RegExp(label));
  }
  assert.doesNotMatch(source, /foundry.*(edge|connector)|source:\s*["']foundry/i);
});

test("motion respects reduced-motion and paused investigation state", () => {
  assert.match(css, /hawk-evidence-river-new/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /hawk-evidence-river-paused/);
  assert.match(css, /animation-play-state:\s*paused/);
});
