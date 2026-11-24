import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildUpstreamHeaders, targetFor } from "./native-gateway.mjs";

test("API proxy preserves public Host while routing to the configured upstream", () => {
  const req = {
    headers: {
      host: "api.hawk.localhost:3443",
      "x-forwarded-host": "attacker.example",
      "x-forwarded-proto": "http",
      accept: "application/json",
    },
    url: "/endpoint-agent/policy",
  };
  const target = targetFor(req);
  assert.deepEqual(target, { host: "127.0.0.1", port: 8000, path: "/endpoint-agent/policy" });
  assert.deepEqual(buildUpstreamHeaders(req.headers, target), {
    ...req.headers,
    host: "api.hawk.localhost:3443",
    "x-forwarded-host": "api.hawk.localhost:3443",
    "x-forwarded-proto": "https",
  });
});

test("ordinary API paths route to API and web paths keep their configured target", () => {
  assert.deepEqual(targetFor({ headers: { host: "hawk.localhost:3443", accept: "application/json" }, url: "/endpoint-agent/heartbeat" }), {
    host: "127.0.0.1", port: 8000, path: "/endpoint-agent/heartbeat",
  });
  assert.deepEqual(targetFor({ headers: { host: "hawk.localhost:3443", accept: "text/html" }, url: "/" }), {
    host: "127.0.0.1", port: 3000, path: "/",
  });
});

test("upgrade requests use the same public Host and forced HTTPS forwarding headers", () => {
  const headers = buildUpstreamHeaders({
    host: "api.hawk.localhost:3443",
    connection: "Upgrade",
    upgrade: "websocket",
    "x-forwarded-host": "spoofed.example",
    "x-forwarded-proto": "http",
  }, { host: "127.0.0.1", port: 8000, path: "/mcp" });
  assert.equal(headers.host, "api.hawk.localhost:3443");
  assert.equal(headers["x-forwarded-host"], "api.hawk.localhost:3443");
  assert.equal(headers["x-forwarded-proto"], "https");
});

test("missing Host uses the fixed gateway fallback", () => {
  const headers = buildUpstreamHeaders({}, { host: "127.0.0.1", port: 8000, path: "/" });
  assert.equal(headers.host, "hawk.localhost:3443");
  assert.equal(headers["x-forwarded-host"], "hawk.localhost:3443");
});

test("gateway defaults to loopback", () => {
  const source = readFileSync(new URL("./native-gateway.mjs", import.meta.url), "utf8");
  assert.match(source, /const listenHost = process\.env\.NATIVE_GATEWAY_HOST \|\| "127\.0\.0\.1";/);
});
