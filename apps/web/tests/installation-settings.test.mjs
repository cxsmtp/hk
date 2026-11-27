import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Settings of the whole server (app/core/installation.py): a workspace admin who is not one of the server's
// administrators sees them read-only, with "Set by the server's administrators." and no save buttons.
const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

test("the console learns from /settings/me whether the person is one of the server's administrators", () => {
  const lib = source("lib/settings-console.ts");
  assert.ok(lib.includes("installationAdmin?: boolean"));
  assert.ok(lib.includes('export const SET_BY_SERVER = "Set by the server\'s administrators."'));
  assert.match(lib, /export function useInstallationAdmin\(\): boolean \| null/);
  // An older server that does not say counts as yes: the server refuses what it does not allow anyway.
  assert.ok(lib.includes("me.installationAdmin !== false"));
  assert.ok(source("lib/api.ts").includes('getSettingsMe: () => request<SettingsMe>("/settings/me")'));
  const note = source("components/server-setting-note.tsx");
  assert.ok(note.includes("SET_BY_SERVER") && note.includes('data-ui="server-setting-note"'));
});

test("every page of a server-wide setting shows it read-only and hides or disables what saves", () => {
  // Pages that read the flag from their own view.
  for (const [page, flag] of [
    ["app/settings/signin/page.tsx", "view?.mayChange === false"],
    ["app/settings/sso/page.tsx", "view?.mayChange === false"],
    ["app/settings/email/page.tsx", "view.mayChange === false"],
    ["app/settings/hands-off/page.tsx", "view?.canSave === false"],
  ]) {
    const text = source(page);
    assert.ok(text.includes(flag), page);
    assert.ok(text.includes("<ServerSettingNote"), page);
    assert.ok(text.includes('className="ro-fieldset" disabled='), page);
  }
  // Pages that read it from /settings/me.
  for (const page of ["app/settings/branding/page.tsx", "app/settings/https/page.tsx", "app/settings/network/page.tsx", "app/settings/updates/page.tsx", "app/settings/backups/page.tsx"]) {
    const text = source(page);
    assert.ok(text.includes("const readOnly = useInstallationAdmin() === false;"), page);
    assert.ok(text.includes("<ServerSettingNote") && text.includes('className="ro-fieldset" disabled={readOnly}'), page);
  }
  // No autosave is wired while read-only.
  for (const page of ["app/settings/signin/page.tsx", "app/settings/sso/page.tsx"]) assert.ok(source(page).includes("if (!form || !loaded || readOnly) return;"), page);
  // Compliance: the settings form and the baseline follow mayChange, with the note.
  const compliance = source("app/settings/compliance/page.tsx");
  assert.ok(compliance.includes("{view?.mayChange && tab === \"desc\" ? (") && compliance.includes("view.readOnlyNote"));
  // Activation codes: no field to apply a code.
  const activation = source("app/settings/activation/page.tsx");
  assert.ok(activation.includes("view.canManage === false") && activation.includes("SET_BY_SERVER"));
  // The self-check's Check now is hidden too.
  assert.ok(source("components/self-check-box.tsx").includes("{readOnly ? null : ("));
  assert.ok(source("app/globals.css").includes("fieldset.ro-fieldset"));
});

test("the guide says who changes the settings of the whole server", () => {
  const people = source("lib/guide/topics/people.ts");
  assert.ok(people.includes('id: "server-settings"') && people.includes("Set by the server's administrators."));
});
