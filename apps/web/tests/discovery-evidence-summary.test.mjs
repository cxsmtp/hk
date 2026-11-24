import test from "node:test";
import assert from "node:assert/strict";
import { summarizeDiscoveryEvidence } from "../src/lib/discovery-evidence-summary.mjs";

test("installed and configured evidence never becomes confirmed use", () => {
  const result = summarizeDiscoveryEvidence([
    { raw_fingerprint: { observation_state: "installed" } },
    { raw_fingerprint: { observation_state: "configured" } },
  ]);
  assert.deepEqual(result.states, ["Configured", "Installed"]);
  assert.equal(result.protection, "Not established by discovery evidence");
});

test("duplicate signal IDs do not inflate counts and imported network observations stay distinct", () => {
  const signal = { id: "one", created_at: "2026-09-01T12:00:00Z", raw_fingerprint: { observation_state: "connection_observed", provenance: "customer_uploaded_export", device_reference: "device-hash" } };
  const result = summarizeDiscoveryEvidence([signal, signal], Date.parse("2026-09-03T12:00:00Z"));
  assert.equal(result.count, 1);
  assert.deepEqual(result.states, ["Connection observed"]);
  assert.equal(result.imported, true);
  assert.equal(result.olderThanDay, true);
  assert.equal(result.devices, 1);
});

test("legacy confidence and missing timestamps do not imply use or freshness", () => {
  const result = summarizeDiscoveryEvidence([{ confidence_signal: { confidence_score: 0.99 } }]);
  assert.deepEqual(result.states, ["Observation type unknown"]);
  assert.equal(result.latest, null);
});
