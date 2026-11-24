import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const actionGraphUrl = new URL("../src/app/runtime-intelligence/action-graph/[id]/page.tsx", import.meta.url);
const auditor = readFileSync(new URL("../src/app/auditor/page.tsx", import.meta.url), "utf8");
const dashboard = readFileSync(new URL("../src/app/dashboard/page.tsx", import.meta.url), "utf8");

test("action graph deep-links back to the matching action trace", () => {
  assert.equal(existsSync(actionGraphUrl), true);
  const source = readFileSync(actionGraphUrl, "utf8");
  assert.match(source, /runtime-intelligence\/action-trace\/\$\{encodeURIComponent\(actionId\)\}/);
});

test("auditor consumes evidence_id deep links", () => {
  assert.match(auditor, /useSearchParams/);
  assert.match(auditor, /searchParams\.get\("evidence_id"\)/);
  assert.match(auditor, /setSelectedProofId/);
});

test("Trust Center CTA returns to the one operational Command Center", () => {
  assert.match(dashboard, /href="\/dashboard\/command-center"/);
  assert.doesNotMatch(dashboard, /href="\/trust-center"/);
});
