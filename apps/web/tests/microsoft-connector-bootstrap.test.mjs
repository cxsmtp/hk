import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const page = fs.readFileSync(new URL("../src/app/integrations/page.tsx", import.meta.url), "utf8");
const api = fs.readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = fs.readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("Microsoft setup supports admin consent and tenant-scoped repair", () => {
  assert.match(page, /Prepare admin consent/);
  assert.match(page, /Save credentials and verify/);
  assert.match(page, /connector_id: microsoftRepairTarget\?\.id/);
  assert.match(page, /create_connector: false/);
  assert.match(page, /create_connector: true/);
  assert.match(page, /client_secret: microsoftClientSecret/);
  assert.match(page, /setMicrosoftClientSecret\(""\)/);
  assert.match(api, /connector_id\?: string/);
  assert.match(types, /updated: boolean/);
});

test("Microsoft setup does not claim consent or persist the client secret", () => {
  assert.match(page, /Microsoft must confirm consent/);
  assert.doesNotMatch(page, /localStorage.*microsoftClientSecret/);
  assert.doesNotMatch(page, /sessionStorage.*microsoftClientSecret/);
});
