import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const login = await readFile(new URL("../src/app/login/page.tsx", import.meta.url), "utf8");
const callback = await readFile(new URL("../src/app/login/oidc/callback/page.tsx", import.meta.url), "utf8");
const api = await readFile(new URL("../src/lib/api.ts", import.meta.url), "utf8");

test("login preserves password sign in and discovers workspace-scoped providers", () => {
  assert.match(login, /api\.login\(email, password\)/);
  assert.match(login, /api\.oidcProviders\(workspace\)/);
  assert.match(login, /api\.oidcStart\(providerKey, workspace\)/);
  assert.match(api, /\/auth\/oidc\/providers\?workspace=/);
});

test("OIDC callback removes fragment before completing a one-use ticket", () => {
  assert.match(callback, /window\.location\.hash/);
  assert.match(callback, /window\.history\.replaceState/);
  assert.match(callback, /api\.oidcComplete\(ticket\)/);
  assert.doesNotMatch(callback, /access_token.*location|refresh_token.*location/);
});
