import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/app/policies/page.tsx", import.meta.url), "utf8");

test("advanced policy console keeps live policy truth visible first", () => {
  assert.match(source, /Running Policies \(Live Enforcement\)/);
  assert.match(source, /Policy packs, assignments, and rollout/);
  assert.ok(source.indexOf("Running Policies (Live Enforcement)") < source.indexOf("Fine-Tune + Publish Policy Version"));
});

test("advanced policy operations use explicit progressive disclosures", () => {
  assert.match(source, /<details[^>]*id="policy-tuning-tools"/);
  assert.match(source, /<details[^>]*id="scoped-policy-tools"/);
  assert.match(source, /<details[^>]*id="policy-pack-tools"/);
  assert.match(source, /Fine-tune and publish/);
  assert.match(source, /Edit scoped rules/);
  assert.match(source, /Create policy pack/);
});

test("advanced disclosures preserve existing policy mutations", () => {
  assert.match(source, /publishTunedVersion/);
  assert.match(source, /saveScopedRules/);
  assert.match(source, /createPack/);
  assert.match(source, /ensurePilotPolicyPack/);
});

test("Policies keeps a clear bridge to user assignment, coverage, and investigation context", () => {
  assert.match(source, /Who and what this policy reaches/);
  assert.match(source, /Open Users &amp; Policy Assignments/);
  assert.match(source, /Open Control Coverage/);
  assert.match(source, /Open Investigation &amp; AI Activity Lineage/);
});
