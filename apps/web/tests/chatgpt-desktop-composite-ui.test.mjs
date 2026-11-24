import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const componentUrl = new URL("../src/components/lifecycle/chatgpt-desktop-asset.tsx", import.meta.url);
const workspace = readFileSync(new URL("../src/components/lifecycle/assets-workspace.tsx", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("ChatGPT composite asset is wired into AI Asset Intelligence", () => {
  assert.equal(existsSync(componentUrl), true, "ChatGPT composite asset component missing");
  assert.match(workspace, /ChatGPTDesktopAsset/);
  assert.match(workspace, /<ChatGPTDesktopAsset\s*\/>/);
  assert.match(api, /chatGPTDesktopAssets/);
  assert.match(api, /chatGPTDesktopControlPlan/);
  assert.match(api, /\/native-controls\/chatgpt-desktop\/assets/);
  assert.match(api, /\/native-controls\/chatgpt-desktop\/control-plan/);
  assert.match(types, /ChatGPTDesktopCompositeAsset/);
  assert.match(types, /ChatGPTDesktopControlPlan/);
});

test("asset shows every required composite boundary and evidence state", () => {
  const component = readFileSync(componentUrl, "utf8");
  for (const label of [
    "Account",
    "Modes",
    "Built-in Browser",
    "Endpoint Floor",
    "File",
    "Process",
    "Network",
    "HTTP semantics",
    "Apps",
    "Custom MCP",
    "Compliance",
    "Codex",
    "Cloud Work",
    "Control Coverage",
    "Evidence",
    "Blind spots",
    "Why this action is controlled",
  ]) {
    assert.match(component, new RegExp(label, "i"), `missing composite boundary: ${label}`);
  }
  for (const state of ["Verified", "Partial", "Experimental", "Unverified", "Unavailable", "Unknown"]) {
    assert.match(component, new RegExp(state), `missing truthful state: ${state}`);
  }
  assert.match(component, /inherits_chrome_extension_coverage/);
  assert.match(component, /native_hook_available/);
  assert.match(component, /No app-wide hook/);
  assert.match(component, /Work\/Codex lifecycle hooks are separate/);
  assert.doesNotMatch(component, /Native hook unavailable/);
  assert.match(component, /verified_dimensions/);
  assert.match(component, /inflation_guard/);
  assert.doesNotMatch(component, /ChatGPT Desktop\s+Protected\s*[✓✔]/i);
});

test("control-plan explorer remains read-only and action specific", () => {
  const component = readFileSync(componentUrl, "utf8");
  assert.match(component, /built_in_browser_upload/);
  assert.match(component, /built_in_browser_download/);
  assert.match(component, /custom_mcp_write/);
  assert.match(component, /codex_local_shell/);
  assert.match(component, /mandatory_enforcement_floors/);
  assert.match(component, /unsatisfied_mandatory_floors/);
  assert.doesNotMatch(component, /Enable enforcement|Disable enforcement/);
});
