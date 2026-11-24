import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const page = readFileSync(new URL("../src/app/integrations/page.tsx", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");
const apiRouter = readFileSync(new URL("../../api/app/api/routers/discovery_source_connections.py", import.meta.url), "utf8");

test("integrations page exposes user-friendly source connection setup flows", () => {
  for (const label of [
    "Source connection setup",
    "customer-owned",
    "No coverage is claimed until validation",
  ]) {
    assert.match(page, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  for (const label of [
    "GitHub repositories",
    "M365 / Teams",
    "Identity directory",
    "SaaS applications",
    "Cloud / AI runtimes",
  ]) {
    assert.match(apiRouter, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(page, /control-coverage\/source-control\/github-repository-boundary/);
});

test("web client has typed source setup catalog contract", () => {
  assert.match(api, /sourceConnectionSetupCatalog/);
  assert.match(api, /discovery\/source-connections\/setup-catalog/);
  assert.match(types, /SourceConnectionSetupFlow/);
  assert.match(types, /SourceConnectionSetupCatalog/);
  for (const family of ["github", "m365_teams", "identity", "saas", "cloud"]) {
    assert.match(types, new RegExp(family));
  }
});
