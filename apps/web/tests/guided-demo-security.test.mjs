import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(new URL("../src/app/guided-demo/page.tsx", import.meta.url), "utf8");

test("guided demo preserves hardened MCP authority and demonstrates fail-closed behavior", () => {
  assert.match(page, /testing MCP zero-trust and denied-scope paths/i);
  assert.match(page, /allowed\.decision !== "block"/);
  assert.match(page, /denied\.decision !== "block"/);
  assert.match(page, /MCP zero-trust gate/);
  assert.doesNotMatch(page, /Expected MCP allowed action decision=allow/);
  assert.doesNotMatch(page, /api\.mintAgentToken/);
});
