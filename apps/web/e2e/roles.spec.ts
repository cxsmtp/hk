import { settingsNav } from "@/lib/settings-menu";
import { ADMIN, acceptTerms, callApi, changeTemporaryPassword, expect, expectNoTokensInBrowserStorage, signIn, signOut, test } from "./support/fixtures";

/** Someone with the Viewer role: read only, and none of the administrators' Settings pages. */

const VIEWER = {
  email: `vera.viewer.${Date.now()}@hawk-e2e.test`,
  name: "Vera Viewer",
  temporaryPassword: "Temporary-Viewer-2026",
  password: "Chosen-Viewer-Pass-2026",
};

const ADMIN_ONLY = [
  "Roles & permissions",
  "Sign-in",
  "Activation codes",
  "Audit log",
  "Connector API activity",
  "Compliance",
  "General",
  "Branding",
  "Email (SMTP)",
  "Single sign-on",
  "HTTPS",
  "Updates",
  "Backups & health",
  "Hands-off",
  "Network & proxy",
  "Get help",
];

test("a viewer cannot see the admin-only Settings items", async ({ page, watch }) => {
  // The viewer's first sign-in answers 403 until their password is changed and the terms accepted; the refused
  // change at the end is a 403 too.
  watch.allow(403, /^\/api\//);
  // A viewer lands on Inventory (/assets), which also asks for surfaces this test installation does not turn on
  // (feature-gated routers answer 404 or 503); that page handles them, and they are not what this test is about.
  watch.allow(404, /^\/api\/(native-controls\/chatgpt-desktop\/assets|control-coverage\/paths)$/);
  watch.allow(503, /^\/api\/ai-iam\/identities$/);

  await signIn(page, ADMIN.email, ADMIN.password);
  const added = await callApi(page, "POST", "/iam/people", {
    email: VIEWER.email,
    name: VIEWER.name,
    role: "viewer",
    password: VIEWER.temporaryPassword,
    sendWelcome: false,
  });
  expect(added.status, JSON.stringify(added.json)).toBeLessThan(300);
  await signOut(page);

  await signIn(page, VIEWER.email, VIEWER.temporaryPassword);
  await changeTemporaryPassword(page, VIEWER.temporaryPassword, VIEWER.password);
  await acceptTerms(page);
  await expectNoTokensInBrowserStorage(page);
  await expect(page.getByRole("button", { name: "Account and administration" })).toContainText(VIEWER.email);

  const me = await callApi(page, "GET", "/settings/me");
  expect(me.status).toBe(200);
  expect(me.json.role).toBe("viewer");
  // Not one of the server's administrators (app/core/installation.py): the whole server's settings are not theirs.
  expect(me.json.installationAdmin).toBe(false);
  const allowed: string[] = settingsNav(me.json.permissions).flatMap((group: { items: Array<{ label: string }> }) => group.items.map((i) => i.label));

  await page.goto("/settings/people");
  await expect(page.getByRole("heading", { level: 1, name: "People", exact: true })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Settings" });
  await expect(nav).toHaveAttribute("aria-busy", "false");
  const shown = await nav.getByRole("link").allInnerTexts();
  expect(shown.map((s) => s.trim())).toEqual(allowed);
  expect(shown).toContain("People");
  for (const label of ADMIN_ONLY) expect(shown, `${label} is not offered to a viewer`).not.toContain(label);
  // Nor offered in the account menu, and People has no "Add person".
  await expect(page.locator("#add-toggle")).toHaveCount(0);

  // And the API refuses them the same, whatever the menu shows.
  const refused = await callApi(page, "PUT", "/settings/branding", { appName: "Not allowed" });
  expect(refused.status).toBe(403);
});
