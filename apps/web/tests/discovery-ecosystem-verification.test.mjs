import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(
  new URL("../src/app/discovery/ecosystems/[ecosystemId]/page.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("ecosystem detail renders evidence-backed autonomous verification truth", () => {
  for (const marker of [
    "Autonomous verification",
    "Verification coverage",
    "Required proof",
    "Optional evidence",
    "Continuously validated",
    "Not yet verified",
    "Known verification limits",
    "Next validation",
  ]) {
    assert.match(page, new RegExp(marker, "i"));
  }
  assert.match(page, /getEcosystemVerification/);
  assert.match(page, /getEcosystemVerificationHistory/);
  assert.doesNotMatch(page, /setStage\(|setVerified\(|forceVerified/i);
});

test("ADV web contracts use the tenant-scoped verification API", () => {
  assert.match(types, /export type EcosystemVerificationProjection/);
  assert.match(types, /required_outcomes: VerificationOutcome\[\]/);
  assert.match(types, /assertion_current: boolean/);
  assert.match(api, /\/discovery\/evidence-resolution\/ecosystems\//);
  assert.match(api, /startEcosystemVerification/);
  assert.match(api, /retryVerificationEpisode/);
});

test("only an authorized administrator receives bounded lifecycle controls", () => {
  assert.match(page, /getSession/);
  assert.match(page, /\["owner", "admin"\]\.includes/);
  assert.match(page, /Start verification/);
  assert.match(page, /Retry verification/);
  assert.match(page, /erg_evaluation_id/);
  assert.match(page, /manual_verification/);
  assert.doesNotMatch(page, /setStage\(|setVerified\(|forceVerified/i);
});
