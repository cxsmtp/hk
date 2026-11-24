import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync("src/app/interaction-security/page.tsx", "utf8");

test("approval rows deep-link only through a stored runtime event id", () => {
  assert.match(source, /actionDetailHref/);
  assert.match(source, /runtime_event_id/);
  assert.match(source, /Open stored Action Detail/);
  assert.match(source, /const approvalDetailHref/);
  assert.match(source, /api\.actionIntegrityDetail\(requestedRuntimeEventId\)/);
  assert.match(source, /detail\.authorisation\?\.approval_request/);
  assert.match(source, /approvalCard\?\.state === "OBSERVED"/);
  assert.match(source, /approvalValue as \{ approval_request_id\?: unknown \}/);
  assert.match(source, /approvalRuntimeBindingVerified/);
});

test("AGUI remains a presentation surface and not an approval authority substitute", () => {
  assert.match(source, /AGUI presentation/);
  assert.doesNotMatch(source, /<Link href="\/agui\/ai-iam-approvals">Approve \/ deny<\/Link>/);
});
