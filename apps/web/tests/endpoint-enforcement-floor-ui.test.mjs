import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const deploy = readFileSync(new URL("../src/components/lifecycle/deploy-workspace.tsx", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("Deploy renders the endpoint consequence boundary without an aggregate protected shortcut", () => {
  for (const phrase of [
    "Endpoint enforcement floor",
    "File control",
    "Process control",
    "Network control",
    "Semantic proxy",
    "Local policy",
    "Minimum floor",
    "Blind spots",
    "Runtime evidence missing",
    "Endpoint identity & health",
    "Signed device status",
    "One-click re-enroll",
    "Auto-renew identity",
    "Signed heartbeat",
    "Policy freshness",
    "Command enforcement acceptance",
  ]) {
    assert.match(deploy, new RegExp(phrase, "i"));
  }
  assert.match(deploy, /endpointFloorStatus/);
  assert.match(deploy, /endpointHealth/);
  assert.match(deploy, /createReenrollmentBundle/);
  assert.match(deploy, /minimum_floor_satisfied/);
  assert.match(deploy, /evidence_refs/);
  assert.doesNotMatch(deploy, /Endpoint Protected = yes/);
});

test("web client has a typed endpoint floor status API", () => {
  assert.match(api, /getEndpointFloorStatus/);
  assert.match(api, /\/endpoint-agent\/floor\/status/);
  assert.match(api, /getEndpointHealth/);
  assert.match(api, /\/endpoint-agent\/health/);
  assert.match(api, /createEndpointReenrollmentAuthorization/);
  assert.match(api, /reenroll-authorizations/);
  assert.match(types, /EndpointEnforcementFloorSummary/);
  assert.match(types, /EndpointHealthSummary/);
  assert.match(types, /EndpointReenrollmentAuthorization/);
  assert.match(types, /file_control/);
  assert.match(types, /process_control/);
  assert.match(types, /network_control/);
  assert.match(types, /semantic_proxy/);
  assert.match(types, /local_policy/);
});
