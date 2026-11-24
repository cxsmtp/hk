import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";


const component = readFileSync("src/components/control-coverage/native-control-matrix.tsx", "utf8");
const page = readFileSync("src/app/surface-coverage/page.tsx", "utf8");
const api = readFileSync("src/lib/api.ts", "utf8");
const types = readFileSync("src/lib/types.ts", "utf8");


test("native control matrix is wired to the existing Surface Coverage page", () => {
  assert.match(page, /NativeControlMatrix/);
  assert.match(page, /<NativeControlMatrix\s*\/>/);
  assert.match(api, /nativeControlProviders/);
  assert.match(api, /nativeControlPoints/);
  assert.match(api, /nativeControlPointHealth/);
  assert.match(api, /configureNativeControlPoint/);
  assert.match(api, /validateNativeControlPoint/);
  assert.match(api, /monitorNativeControlPoint/);
  assert.match(api, /enforceNativeControlPoint/);
  assert.match(api, /disableNativeControlPoint/);
});


test("matrix shows capability truth, health, blind spots, and selection explanation", () => {
  for (const label of [
    "Control Capability Matrix",
    "Why this control point?",
    "Verified",
    "Unverified",
    "Unknown",
    "Known blind spots",
    "Provider version",
    "Policy freshness",
    "Accepted provider proof",
    "Authorization",
    "Parameter binding",
    "Execution proof",
    "Provider permission",
    "Hawk approval binding",
    "Approval correlation",
    "Tool failure visibility",
    "Execution correlation",
    "Config change visibility",
    "Function tool",
    "Function parameters",
    "Function target",
    "Model request",
    "Model response",
    "Local MCP",
    "Hosted MCP",
    "Direct API",
    "Admin lifecycle",
    "Observed p95 latency",
    "Live signed callback observed",
    "Enforcement feature enabled",
    "Active for enforcement",
  ]) {
    assert.ok(component.includes(label), `missing UI label: ${label}`);
  }
  assert.match(component, /primaryControlPoint/);
  assert.match(component, /rejected_candidates/);
  assert.match(component, /function_tool_control/);
  assert.match(component, /function_tool_parameter_binding/);
  assert.match(component, /function_tool_target_binding/);
  assert.match(component, /model_request_control/);
  assert.match(component, /model_response_control/);
  assert.match(component, /local_mcp_control/);
  assert.match(component, /hosted_mcp_control/);
  assert.match(component, /direct_api_control/);
});


test("provider compatibility keeps deployment facts separate and never invents installation", () => {
  for (const label of [
    "Provider Compatibility",
    "Installed",
    "Configured",
    "Healthy",
    "Validated",
    "Enforced",
    "Unknown",
  ]) {
    assert.match(component, new RegExp(label));
  }
  assert.match(component, /Installed[\s\S]*Unknown/);
  assert.match(component, /validation_current/);
  assert.match(component, /real_acceptance_current/);
  assert.match(component, /enforcement_feature_active/);
  assert.match(component, /authoritative/);
  assert.match(component, /health_state === "healthy"/);
  assert.doesNotMatch(component, /installed:\s*true/);
  assert.match(component, /manifests\.flatMap/);
  assert.match(component, /const matchingPoints = points\.filter/);
  assert.match(component, /function configuredFactState/);
  assert.match(component, /function healthyFactState/);
  assert.match(component, /point\.state === "configuring"/);
  assert.match(component, /point\.health_state === "unknown"/);
});


test("frontend types preserve non-boolean capability and verification states", () => {
  assert.match(types, /export type NativeCapabilityLevel/);
  assert.match(types, /"inline_bound"/);
  assert.match(types, /"unavailable"/);
  assert.match(types, /export type NativeVerificationStatus/);
  assert.match(types, /"broken"/);
  assert.match(types, /NativeControlSelection/);
});


test("degraded control points expose the explicit admin reconfiguration path", () => {
  assert.match(
    component,
    /!\["disabled", "degraded"\]\.includes\(selectedPoint\.state\)/,
  );
  assert.doesNotMatch(
    component,
    /selectedPoint\.state !== "disabled"/,
  );
});
