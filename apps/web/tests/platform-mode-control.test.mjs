import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const apiSource = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const typesSource = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");
const commandCenterSource = readFileSync(
  new URL("../src/app/dashboard/command-center/page.tsx", import.meta.url),
  "utf8",
);
const controlUrl = new URL("../src/components/platform-mode-control.tsx", import.meta.url);
const controlSource = existsSync(controlUrl) ? readFileSync(controlUrl, "utf8") : "";

test("platform mode client uses the audited tenant authority", () => {
  assert.match(typesSource, /export type PlatformMode = "discovery" \| "enforce"/);
  assert.match(typesSource, /export type PlatformModeResponse/);
  assert.match(apiSource, /getPlatformMode: \(\) => request<PlatformModeResponse>\("\/system\/platform-mode"\)/);
  assert.match(
    apiSource,
    /updatePlatformMode:[\s\S]*?method: "POST"[\s\S]*?JSON\.stringify\(\{ platform_mode: platformMode \}\)/,
  );
});

test("Command Center mounts a real platform mode control before priority actions", () => {
  const defaultStart = commandCenterSource.indexOf(
    'if (process.env.NEXT_PUBLIC_LEGACY_COMMAND_CENTER !== "true")',
  );
  const legacyStart = commandCenterSource.indexOf("\n  return (", defaultStart);
  const defaultBranch = commandCenterSource.slice(defaultStart, legacyStart);

  assert.match(commandCenterSource, /import \{ PlatformModeControl \}/);
  assert.match(defaultBranch, /<PlatformModeControl compact \/>/);
  assert.ok(defaultBranch.indexOf("<TopActionsNow") < defaultBranch.indexOf("<PlatformModeControl compact />"));
  assert.match(defaultBranch, /Scope & filters[\s\S]*?<PlatformModeControl compact \/>/);
});

test("Command Center can use the compact admin control without changing authority behavior", () => {
  assert.match(controlSource, /export function PlatformModeControl\(\{ compact = false \}/);
  assert.match(controlSource, /if \(compact\)/);
  assert.match(controlSource, /Tenant mode/);
  assert.match(controlSource, /View decision evidence/);
});

test("platform mode control is server-confirmed, admin-gated, and fail-safe", () => {
  assert.match(controlSource, /api\.getPlatformMode\(\)/);
  assert.match(controlSource, /api\.updatePlatformMode\(targetMode\)/);
  assert.match(controlSource, /const \[confirmingEnforce, setConfirmingEnforce\]/);
  assert.match(controlSource, /\["owner", "admin"\]\.includes\(role\)/);
  assert.match(controlSource, /if \(targetMode === "enforce"\)[\s\S]*?setConfirmingEnforce\(true\)/);
  assert.match(controlSource, /window\.addEventListener\("focus", refreshConfirmedMode\)/);
  assert.match(controlSource, /const updated = await api\.updatePlatformMode\(targetMode\)/);
  assert.match(controlSource, /setConfirmedMode\(updated\.platform_mode\)/);
  assert.match(controlSource, /setConfirmingEnforce\(false\)[\s\S]*?await api\.getPlatformMode\(\)/);
  assert.match(controlSource, /setConfirmedMode\(refreshed\.platform_mode\)/);
  assert.match(controlSource, /Mode changed to[\s\S]*?revalidation/i);
  assert.match(controlSource, /href="\/interaction-security"/);
  assert.match(controlSource, /does not prove endpoint acknowledgement/i);
});

test("monitor rollback is immediate while Enforce requires confirmation", () => {
  assert.match(controlSource, /onClick=\{\(\) => requestMode\("discovery"\)\}/);
  assert.match(controlSource, /onClick=\{\(\) => requestMode\("enforce"\)\}/);
  assert.match(controlSource, /confirmingEnforce \?/);
  assert.match(controlSource, /Confirm Enforce/);
  assert.match(controlSource, /Cancel/);
});
