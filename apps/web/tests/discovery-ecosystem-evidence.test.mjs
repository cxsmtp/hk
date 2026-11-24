import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/app/discovery/ecosystems/[ecosystemId]/page.tsx", import.meta.url),
  "utf8",
);

test("ecosystem evidence detail exposes the approved explainability projection", () => {
  for (const marker of [
    "Why Hawk believes this ecosystem exists",
    "Capability genome",
    "Evidence contributors",
    "Evidence timeline",
    "Outstanding contradictions",
    "Collectors",
    "Last validation",
    "Recommended actions",
    "Advanced graph drill-down",
    "hawk-river",
  ]) {
    assert.match(source.toLowerCase(), new RegExp(marker.toLowerCase().replaceAll(" ", "\\s+")));
  }
});
