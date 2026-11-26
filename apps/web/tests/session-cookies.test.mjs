import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { registerProductionAliases } from "./fixtures/ts-alias-hooks.mjs";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

// A browser of sorts: storage, a cookie jar the page can read (the CSRF cookie; the API's HttpOnly ones it cannot)
// and a fetch that answers from a queue and keeps what it was asked.
registerProductionAliases();
const storage = new Map();
globalThis.window = globalThis;
globalThis.localStorage = {
  getItem: (key) => (storage.has(key) ? storage.get(key) : null),
  setItem: (key, value) => storage.set(key, String(value)),
  removeItem: (key) => storage.delete(key),
};
globalThis.document = { cookie: "" };
if (typeof globalThis.dispatchEvent !== "function") globalThis.dispatchEvent = () => true;
const answers = [];
const asked = [];
globalThis.fetch = async (url, init = {}) => {
  asked.push({ url: String(url), init, headers: new Headers(init.headers || {}) });
  const next = answers.shift();
  if (!next) throw new Error(`no answer queued for ${url}`);
  if (next.cookie !== undefined) globalThis.document.cookie = next.cookie;
  return new Response(next.body ?? "{}", { status: next.status ?? 200, headers: { "content-type": "application/json" } });
};
const { api, signOut } = await import("../src/lib/api.ts");
const { getSession, setSession } = await import("../src/lib/auth.ts");

const PERSON = { id: "u1", email: "ada@example.com", full_name: "Ada" };

function reset() {
  storage.clear();
  answers.length = 0;
  asked.length = 0;
  globalThis.document.cookie = "";
}

test("signing in keeps no token in the browser's storage, and drops what older versions kept", async () => {
  reset();
  storage.set("ai-control-plane-session", JSON.stringify({ accessToken: "old-access", refreshToken: "old-refresh", tenantId: "t1" }));
  answers.push({
    cookie: "__Host-hawk_csrf=csrf-1",
    body: JSON.stringify({ access_token: "", refresh_token: "", token_type: "bearer", user: PERSON, tenants: [{ id: "t1", name: "T", role: "owner" }], selected_tenant_id: "t1" }),
  });
  await api.login("ada@example.com", "a long enough password");
  const sent = asked[0];
  assert.equal(sent.headers.get("X-Hawk-Session"), "cookie");
  assert.equal(sent.init.credentials, "include");
  // What a sign-in page passes, tokens included, is stored without them.
  setSession({ tenantId: "t1", userRole: "owner", user: PERSON, accessToken: "x", refreshToken: "y" });
  const kept = JSON.stringify([...storage.entries()]);
  assert.doesNotMatch(kept, /old-access|old-refresh|"x"|"y"|accessToken|refreshToken/);
  assert.equal(storage.has("ai-control-plane-session"), false);
  assert.deepEqual(getSession(), { tenantId: "t1", userRole: "owner", user: PERSON });
});

test("every request goes with the session cookie and the CSRF header, never a bearer token", async () => {
  reset();
  setSession({ tenantId: "t1", userRole: "owner", user: PERSON });
  globalThis.document.cookie = "other=1; __Host-hawk_csrf=csrf-2";
  answers.push({ body: JSON.stringify({ id: "u1", email: PERSON.email, full_name: "Ada", tenants: [] }) });
  await api.me();
  answers.push({ body: JSON.stringify({ terms: {} }) });
  await api.acceptTerms({ version: "1" });
  for (const { headers, init } of asked) {
    assert.equal(init.credentials, "include");
    assert.equal(headers.get("Authorization"), null);
    assert.equal(headers.get("X-CSRF-Token"), "csrf-2");
    assert.equal(headers.get("X-Tenant-ID"), "t1");
  }
});

test("a refused request is refreshed through the cookie, then tried again", async () => {
  reset();
  setSession({ tenantId: "t1", userRole: "owner", user: PERSON });
  globalThis.document.cookie = "hawk_csrf=csrf-3";
  answers.push({ status: 401, body: JSON.stringify({ detail: "Invalid token" }) });
  answers.push({ body: JSON.stringify({ access_token: "", refresh_token: "", token_type: "bearer", expires_in: 1800 }) });
  answers.push({ body: JSON.stringify({ id: "u1", email: PERSON.email, full_name: "Ada", tenants: [] }) });
  const me = await api.me();
  assert.equal(me.id, "u1");
  assert.deepEqual(asked.map((call) => new URL(call.url).pathname), ["/auth/me", "/auth/refresh", "/auth/me"]);
  const refresh = asked[1];
  assert.equal(refresh.init.method, "POST");
  assert.equal(refresh.init.credentials, "include");
  assert.equal(refresh.headers.get("X-CSRF-Token"), "csrf-3");
  // No refresh token in the body: it is in the cookie only the API can read.
  assert.deepEqual(JSON.parse(refresh.init.body), {});
  assert.ok(getSession());
});

test("a refresh refused twice signs out; once (another tab rotated the cookie) it is tried again", async () => {
  reset();
  setSession({ tenantId: "t1", userRole: "owner", user: PERSON });
  answers.push({ status: 401, body: "{}" });
  answers.push({ status: 401, body: JSON.stringify({ detail: "Refresh token revoked or unknown" }) });
  answers.push({ body: "{}" });
  answers.push({ body: JSON.stringify({ id: "u1", email: PERSON.email, full_name: "Ada", tenants: [] }) });
  assert.equal((await api.me()).id, "u1");
  assert.ok(getSession(), "the second try succeeded: still signed in");

  asked.length = 0;
  answers.push({ status: 401, body: "{}" });
  answers.push({ status: 401, body: "{}" });
  answers.push({ status: 401, body: "{}" });
  await assert.rejects(api.me());
  assert.deepEqual(asked.map((call) => new URL(call.url).pathname), ["/auth/me", "/auth/refresh", "/auth/refresh"]);
  assert.equal(getSession(), null);
});

test("signing out asks the API to revoke the refresh token and clear the cookies, and forgets the session", async () => {
  reset();
  setSession({ tenantId: "t1", userRole: "owner", user: PERSON });
  globalThis.document.cookie = "__Host-hawk_csrf=csrf-4";
  answers.push({ body: JSON.stringify({ ok: true }) });
  await signOut();
  assert.equal(new URL(asked[0].url).pathname, "/auth/refresh/sign-out");
  assert.equal(asked[0].init.method, "POST");
  assert.equal(asked[0].headers.get("X-CSRF-Token"), "csrf-4");
  assert.equal(getSession(), null);

  // Even when the API cannot be reached.
  setSession({ tenantId: "t1", userRole: "owner", user: PERSON });
  await signOut();
  assert.equal(getSession(), null);
});

test("no page or hook reads, stores or sends a token itself", () => {
  for (const path of [
    "lib/auth.ts",
    "lib/settings-console.ts",
    "components/app-shell.tsx",
    "components/access-gate.tsx",
    "components/topbar.tsx",
    "app/login/page.tsx",
    "app/login/oidc/callback/page.tsx",
    "app/join/page.tsx",
    "hooks/use-simulation-stream.ts",
    "hooks/use-runtime-intelligence-stream.ts",
  ]) {
    const text = source(path);
    assert.doesNotMatch(text, /accessToken|refreshToken|updateSessionTokens|Bearer \$\{/, path);
    assert.doesNotMatch(text, /\.access_token|\.refresh_token/, path);
  }
  const api = source("lib/api.ts");
  assert.doesNotMatch(api, /"Authorization"|\bAuthorization:|Bearer |\baccessToken\b|\brefreshToken\b|\.access_token|\.refresh_token/);
  assert.match(source("hooks/use-simulation-stream.ts"), /credentials: "include"/);
});

test("a developer's API on another loopback port takes the page's name, so the cookies are same-site", async () => {
  const { normalizeApiBaseUrl } = await import("../src/lib/api-url.ts");
  assert.equal(normalizeApiBaseUrl("/api/", "hawk.example.com"), "/api");
  assert.equal(normalizeApiBaseUrl("http://127.0.0.1:8000", "localhost"), "http://localhost:8000");
  assert.equal(normalizeApiBaseUrl("http://localhost:8000", "127.0.0.1"), "http://127.0.0.1:8000");
  assert.equal(normalizeApiBaseUrl("http://localhost:8000", ""), "http://127.0.0.1:8000");
  assert.equal(normalizeApiBaseUrl("https://api.example.com/", "hawk.example.com"), "https://api.example.com");
});
