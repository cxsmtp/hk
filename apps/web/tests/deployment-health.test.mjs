import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const coverageUrl = new URL("../src/app/surface-coverage/page.tsx", import.meta.url);
const commandCenter = readFileSync(new URL("../src/app/dashboard/command-center/page.tsx", import.meta.url), "utf8");

test("deployment surfaces route exists and states inline limitations honestly", () => {
  assert.equal(existsSync(coverageUrl), true);
  const source = readFileSync(coverageUrl, "utf8");
  for (const phrase of [
    "Browser Extension",
    "MCP / Developer Gateway",
    "LLM Gateway / SDK",
    "Microsoft Foundry",
    "Microsoft Copilot",
    "Desktop / SWG / Local Proxy",
    "Inline when routed",
    "Telemetry / external-required",
    "limitation",
  ]) {
    assert.match(source, new RegExp(phrase.replaceAll("/", "\\/")));
  }
});

test("Command Center exposes operational pilot and deployment health", () => {
  assert.match(commandCenter, /title="Pilot Health"/);
  for (const field of ["schema_health", "policy_sync", "telemetry", "deployment_hardening"]) {
    assert.match(commandCenter, new RegExp(field));
  }
});

