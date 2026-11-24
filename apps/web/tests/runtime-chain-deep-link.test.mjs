import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const chainGraphRoute = new URL(
  "../src/app/runtime-intelligence/chains/[id]/graph/page.tsx",
  import.meta.url,
);
const chainEvidenceRoute = new URL(
  "../src/app/runtime-intelligence/chains/[id]/evidence/page.tsx",
  import.meta.url,
);
const activityMap = readFileSync(
  new URL("../src/app/runtime-intelligence/activity-map/page.tsx", import.meta.url),
  "utf8",
);

test("runtime chain graph deep-link opens the activity map for the requested chain", () => {
  assert.equal(existsSync(chainGraphRoute), true);
  const source = readFileSync(chainGraphRoute, "utf8");
  assert.match(source, /runtime-intelligence\/activity-map\?chain_id=/);
  assert.match(source, /encodeURIComponent/);
});

test("activity map consumes and loads the chain_id query parameter", () => {
  assert.match(activityMap, /searchParams\.get\("chain_id"\)/);
  assert.match(activityMap, /api\.runtimeChainGraph\(requestedChainId\)/);
  assert.match(activityMap, /setLoadedChainId\(requestedChainId\)/);
});

test("runtime chain evidence deep-link renders the chain evidence endpoint", () => {
  assert.equal(existsSync(chainEvidenceRoute), true);
  const source = readFileSync(chainEvidenceRoute, "utf8");
  assert.match(source, /api\.runtimeAgenticChainEvidence\(chainId\)/);
  assert.match(source, /Evidence bundles/);
  assert.match(source, /Evidence nodes/);
});
