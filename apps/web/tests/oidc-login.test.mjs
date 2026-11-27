import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const login = await readFile(new URL("../src/app/login/page.tsx", import.meta.url), "utf8");
const callback = await readFile(new URL("../src/app/login/oidc/callback/page.tsx", import.meta.url), "utf8");
const api = await readFile(new URL("../src/lib/api.ts", import.meta.url), "utf8");

test("login is email and password only, with single sign-on found without a workspace box", () => {
  assert.match(login, /api\.login\(email, password\)/);
  // No workspace box: ?workspace= is an optional pre-fill only.
  assert.doesNotMatch(login, /htmlFor="login-workspace"|>Workspace</);
  assert.match(login, /workspaceFromAddress\(window\.location\.search\)/);
  assert.match(login, /api\.oidcProviders\(workspace\)/);
  assert.match(login, /api\.oidcStart\(providerKey, workspace\)/);
  // Several workspaces: the email's domain finds the provider.
  assert.match(login, /api\.oidcDiscover\(address\)/);
  assert.match(login, /Continue with single sign-on/);
  assert.match(api, /\/auth\/oidc\/providers\$\{workspace \? `\?workspace=/);
  assert.match(api, /"\/auth\/oidc\/discover"/);
  // The workspace used last in this browser is opened again.
  assert.match(login, /workspaceToOpen\(result\.tenants, result\.selected_tenant_id, rememberedWorkspace\(\)\)/);
});

test("OIDC callback removes fragment before completing a one-use ticket", () => {
  assert.match(callback, /window\.location\.hash/);
  assert.match(callback, /window\.history\.replaceState/);
  assert.match(callback, /api\.oidcComplete\(ticket\)/);
  assert.doesNotMatch(callback, /access_token.*location|refresh_token.*location/);
});
