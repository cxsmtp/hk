import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../", import.meta.url);

function source(relativePath) {
  return readFileSync(new URL(relativePath, root), "utf8");
}

test("Connector Control Room exposes the approved evidence-backed language and links", () => {
  const controlRoom = source("src/components/integrations/connector-control-room.tsx");
  const state = source("src/lib/connector-control-room-state.ts");
  const renderedContract = `${controlRoom}\n${state}`;

  for (const phrase of [
    "Integrations",
    "Run live evaluation",
    "Monitor-only",
    "Inline when Chrome-routed",
    "Pre-Action Blocked",
    "Unknown",
    "Not Covered",
  ]) {
    assert.match(renderedContract, new RegExp(phrase));
  }

  assert.match(controlRoom, /\/auditor\?evidence_id=/);
  assert.doesNotMatch(controlRoom, /raw_payload|message_body|prompt_preview/i);
  assert.match(controlRoom, /deriveGmailBrowserPresentation/);
  assert.match(controlRoom, /selectMatchingEvaluation/);
  assert.match(controlRoom, /canLinkVerifiedEvidence/);
  assert.match(controlRoom, /Telemetry-only/);
  assert.match(controlRoom, /No inline Gmail action observed/);
  assert.match(controlRoom, /latest_pull\?\.error/);
  assert.doesNotMatch(controlRoom, /integrity_status === "valid" \? "covered"/);
});

test("Connector Control Room is an operational category catalog", () => {
  const controlRoom = source("src/components/integrations/connector-control-room.tsx");
  assert.match(controlRoom, /All categories/);
  assert.match(controlRoom, /Available integrations/);
  assert.match(controlRoom, /Planned \/ unsupported/);
  assert.match(controlRoom, /Never configured/);
  for (const capability of ["Discover", "Authorize", "Prove"]) {
    assert.match(controlRoom, new RegExp(capability));
  }
  assert.match(controlRoom, /normalizeConnectorCategory/);
  assert.match(controlRoom, /deriveConnectorReadiness/);
  assert.match(controlRoom, /deriveConnectorCapabilities/);
  assert.match(controlRoom, /filteredAvailable/);
  assert.match(controlRoom, /filteredPlanned/);
  assert.match(controlRoom, /filteredAvailable\.map/);
  assert.match(controlRoom, /filteredPlanned\.map/);
});

test("connector evaluation has a typed API contract", () => {
  const api = source("src/lib/api.ts");
  const types = source("src/lib/types.ts");

  assert.match(api, /connectorEvaluation:\s*\(connectorId: string\)[\s\S]*\/monitoring\/connectors\/\$\{encodeURIComponent\(connectorId\)\}\/evaluation/);
  assert.match(types, /export type ConnectorEvaluation\s*=/);
  assert.match(types, /connector_path:[\s\S]*prove: ConnectorCoverageState/);
  assert.match(types, /browser_path:[\s\S]*prove: ConnectorCoverageState/);
});

test("Integrations keeps prior evaluation state while refreshing the selected connector", () => {
  const page = source("src/app/integrations/page.tsx");

  assert.match(page, /api\.connectorEvaluation/);
  assert.match(page, /api\.pullConnectorNow/);
  assert.match(page, /setEvaluating\(true\)/);
  assert.match(page, /setEvaluationError/);
  assert.match(page, /ConnectorControlRoom/);
  assert.match(page, /selectedConnectorRef/);
  assert.match(page, /shouldApplyConnectorOperation/);
  assert.match(page, /verifiedEvaluation\.latest_pull\?\.status === "error"/);
  assert.doesNotMatch(page, /setEvaluation\(null\)[\s\S]{0,240}pullConnectorNow/);
});
