import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = readFileSync(new URL("../src/lib/presentation-state.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
const { resolvePresentationState } = await import(`data:text/javascript,${encodeURIComponent(compiled)}`);

test("presentation state distinguishes loading, populated, empty, unavailable, and stale data", () => {
  assert.equal(resolvePresentationState({ loading: true, hasData: false }), "loading");
  assert.equal(resolvePresentationState({ loading: false, hasData: true }), "ready-populated");
  assert.equal(resolvePresentationState({ loading: false, hasData: false }), "ready-empty");
  assert.equal(resolvePresentationState({ loading: false, hasData: false, unavailable: true }), "unavailable");
  assert.equal(resolvePresentationState({ loading: false, hasData: true, stale: true }), "stale");
});

test("a failed refresh preserves existing observations as stale instead of empty or unavailable", () => {
  assert.equal(resolvePresentationState({ loading: false, hasData: true, unavailable: true }), "stale");
  assert.equal(resolvePresentationState({ loading: true, hasData: true }), "stale");
});

test("operational state only offers retry and sign in when callers supply working actions", () => {
  const view = readFileSync(new URL("../src/components/operational-state.tsx", import.meta.url), "utf8");
  assert.match(view, /export function OperationalState/);
  assert.match(view, /onRetry \?/);
  assert.match(view, /signInHref \?/);
  assert.match(view, /state === "ready-populated"/);
  assert.doesNotMatch(view, /window\.location\.reload|href="#"/);
});
