import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("Command Center offers persona homes and deployment-surface focus", () => {
  const component = readFileSync(new URL("../src/components/lifecycle/persona-home.tsx", import.meta.url), "utf8");
  const commandCenter = readFileSync(new URL("../src/app/dashboard/command-center/page.tsx", import.meta.url), "utf8");
  for (const label of ["CISO", "Operator", "Auditor", "Developer", "Browser", "Endpoint", "MCP", "LLM", "Microsoft"]) {
    assert.match(component, new RegExp(label));
  }
  assert.match(commandCenter, /<PersonaHome/);
  assert.match(component, /Open workspace/);
  assert.match(component, /href={activePersona\.href}/);
});
