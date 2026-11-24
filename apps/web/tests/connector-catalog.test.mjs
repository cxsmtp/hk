import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/lib/connector-catalog.ts", import.meta.url), "utf8");

test("connector categories are normalized into customer-facing deployment groups", () => {
  assert.match(source, /export function normalizeConnectorCategory/);
  assert.match(source, /Agent and model platforms/);
  assert.match(source, /MCP gateways and proxies/);
  assert.match(source, /Browser, desktop, IDE and CLI/);
  assert.match(source, /Enterprise applications/);
  assert.match(source, /Endpoint, EDR, SASE and network controls/);
  assert.match(source, /Cloud and AI runtimes/);
  assert.match(source, /SDK and application bindings/);
  assert.match(source, /microsoft/);
});

test("catalog readiness excludes stubs and preview adapters from coverage", () => {
  assert.match(source, /export function deriveConnectorReadiness/);
  assert.match(source, /delivery: "planned"[\s\S]*coverageEligible: false/);
  assert.match(source, /delivery: "preview"[\s\S]*coverageEligible: false/);
  assert.match(source, /delivery: "production"[\s\S]*coverageEligible: true/);
  assert.match(source, /Verified evidence still required/);
});

test("catalog capabilities keep provider collection separate from authorization", () => {
  assert.match(source, /export function deriveConnectorCapabilities/);
  assert.match(source, /authorize: false/);
  assert.match(source, /discover:/);
  assert.match(source, /prove:/);
});
