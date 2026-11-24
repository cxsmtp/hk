import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/components/lifecycle/policy-builder.tsx", import.meta.url), "utf8");

test("Protect defaults to an accepted create and list-first policy screen", () => {
  assert.doesNotMatch(source, /Policy Control Room/);
  assert.match(source, /title="Policies"/);
  assert.match(source, /Create policy/);
  assert.match(source, /Search policies/);
  assert.match(source, /All statuses/);
  assert.match(source, /Running version/);
  assert.match(source, /Observed interventions/);
  assert.match(source, /runningPolicyStatus/);
});

test("policy metrics remain measurable and conservative", () => {
  assert.match(source, /Total policies/);
  assert.match(source, /Active policies/);
  assert.match(source, /Running versions/);
  assert.match(source, /observedBlocks/);
  assert.doesNotMatch(source, /effectiveness score|coverage score/i);
});

test("business intent builder opens in a wide accessible drawer", () => {
  assert.match(source, /<DetailDrawer/);
  assert.match(source, /size="wide"/);
  assert.match(source, /builderOpen/);
  for (const label of ["Intent", "Scope", "Action", "Validate", "Publish"]) {
    assert.match(source, new RegExp(`"${label}"`));
  }
});

test("publish remains bound to the existing immutable API path", () => {
  assert.match(source, /api\.createPolicyVersion/);
  assert.match(source, /api\.updatePolicyVersionScopedRules/);
  assert.match(source, /api\.updatePolicyPack/);
  assert.match(source, /not a simulation/);
  assert.match(source, /href="\/policies"/);
});

test("Policy Control Room never presents failed API loads as measured zero", () => {
  assert.match(source, /loadError/);
  assert.match(source, /Policy data is unavailable/);
  assert.match(source, /loadError \? "Unknown"/);
});
