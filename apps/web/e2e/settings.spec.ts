import { SETTINGS_GROUPS } from "@/lib/settings-menu";
import { ADMIN, callApi, expect, signIn, test } from "./support/fixtures";

/** Settings as the first administrator (Owner): every page of the menu, and the pages that change something. */

test.beforeEach(async ({ page }) => {
  await signIn(page, ADMIN.email, ADMIN.password);
});

const ITEMS = SETTINGS_GROUPS.flatMap((group: { items: Array<{ href: string; label: string }> }) => group.items);

test("every Settings page opens with its heading, no console errors and no API errors", async ({ page }) => {
  // Every page of settings-menu.mjs, in the menu's order, each opened from the address bar.
  expect(ITEMS.length).toBeGreaterThan(10);
  for (const item of ITEMS) {
    await test.step(item.label, async () => {
      const response = await page.goto(item.href);
      expect(response?.status(), item.href).toBe(200);
      await expect(page.getByRole("heading", { level: 1, name: item.label, exact: true })).toBeVisible();
      // The Settings menu beside it, with this page marked as the one open.
      const nav = page.getByRole("navigation", { name: "Settings" });
      await expect(nav).toHaveAttribute("aria-busy", "false");
      await expect(nav.getByRole("link", { name: item.label, exact: true })).toHaveAttribute("aria-current", "page");
      // Let the page's own requests settle before the next one (the watch fails the test on any error answer).
      await page.waitForLoadState("networkidle");
    });
  }
});

test("People: add a person and see them in the list", async ({ page }) => {
  const email = `pat.e2e.${Date.now()}@hawk-e2e.test`;
  await page.goto("/settings/people");
  await expect(page.getByRole("heading", { level: 1, name: "People", exact: true })).toBeVisible();
  await page.locator("#add-toggle").click();
  const form = page.locator("form#add");
  await form.locator("input[name=email]").fill(email);
  await form.locator("input[name=name]").fill("Pat Example");
  await form.locator("input[name=title]").fill("Security Analyst");
  await form.locator("select[name=role]").selectOption("operator");
  await form.locator("input[name=password]").fill("Temporary-Person-2026");
  await form.getByRole("button", { name: "Add person", exact: true }).click();
  await expect(form.locator(".err")).toHaveText("");
  await expect(form.locator(".callout")).toContainText(email);
  // In the list, with their role.
  await page.locator("#q").fill("Pat Example");
  const row = page.locator("tr", { hasText: email });
  await expect(row).toBeVisible();
  await expect(row.locator("select.inline-sel").first()).toHaveValue("operator");
});

test("Roles & permissions shows the permission grid", async ({ page }) => {
  await page.goto("/settings/roles");
  await expect(page.getByRole("heading", { level: 1, name: "Roles & permissions" })).toBeVisible();
  const grid = page.locator("table.matrix");
  await expect(grid).toBeVisible();
  for (const role of ["Owner", "Admin", "Auditor", "Operator", "Viewer"]) {
    await expect(grid.locator("thead th", { hasText: role }).first()).toBeVisible();
  }
  // One tick box per role and permission: Owner's and Admin's locked on, the others' editable.
  const boxes = grid.getByRole("checkbox");
  expect(await boxes.count()).toBeGreaterThan(5 * 10);
  const ownerBoxes = grid.getByRole("checkbox", { name: /^Owner: / });
  expect(await ownerBoxes.count()).toBeGreaterThan(10);
  await expect(ownerBoxes.first()).toBeChecked();
  await expect(ownerBoxes.first()).toBeDisabled();
  await expect(grid.getByRole("checkbox", { name: /^Viewer: / }).first()).toBeEnabled();
});

test("Branding: a new product name shows in the menu", async ({ page }) => {
  const name = `Kestrel ${Date.now() % 100000}`;
  await page.goto("/settings/branding");
  await expect(page.getByRole("heading", { level: 1, name: "Branding" })).toBeVisible();
  const field = page.locator("input[name=appName]");
  await expect(field).not.toHaveValue("");
  const saved = page.waitForResponse((r) => r.url().endsWith("/api/settings/branding") && r.request().method() === "PUT");
  await field.fill(name);
  expect((await saved).status()).toBe(200);
  await expect(page.getByText(/All changes are saved ✓/)).toBeVisible();
  // The menu's head follows at once, and keeps it after a reload (it is the server's setting, not the page's).
  await expect(page.getByRole("link", { name: `${name} home` })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("link", { name: `${name} home` })).toContainText(name);
  await page.goto("/settings/people");
  await expect(page.getByRole("link", { name: `${name} home` })).toContainText(name);
});

test("Two-step sign-in: setting it up shows a QR code", async ({ page }) => {
  await page.goto("/settings/two-step");
  await expect(page.getByRole("heading", { level: 1, name: "Two-step sign-in" })).toBeVisible();
  await page.getByRole("button", { name: "Turn on two-step sign-in" }).click();
  const key = page.locator("[data-ui=two-step-key]");
  await expect(key.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  const path = key.locator("svg path");
  expect(((await path.getAttribute("d")) || "").length).toBeGreaterThan(100);
  await expect(key.locator("code")).toHaveText(/^[A-Z2-7 ]{16,}$/);
  // Not confirmed with a code, so it stays off.
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Turn on two-step sign-in" })).toBeVisible();
});

test("Licence shows the installation ID and the trial, gives the licence request and refuses a file that is not a licence", async ({ page, watch }) => {
  // The refused upload is expected here.
  watch.allow(400, /^\/api\/licence\/import$/);
  await page.goto("/settings/activation");
  await expect(page.getByRole("heading", { level: 1, name: "Licence" })).toBeVisible();
  const status = await callApi(page, "GET", "/licence/status");
  expect(status.status).toBe(200);
  // A fresh installation: its own ID, and the 3-day trial from its first start.
  expect(status.json.installationId).toMatch(/^HK-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  expect(status.json.trial.active).toBe(true);
  expect(Date.parse(status.json.trial.end) - Date.parse(status.json.trial.start)).toBe(72 * 60 * 60 * 1000);
  await expect(page.locator("[data-ui=installation-id] code")).toHaveText(status.json.installationId);
  await expect(page.locator("[data-ui=licence-product]")).toContainText("Hawk AI · Trial · Until");
  // The admins' banner shows the time left.
  await expect(page.locator("[data-ui=licence-banner]")).toContainText("Hawk AI trial:");
  // The server's administrator gets the request and the upload, without the read-only note.
  expect(status.json.canManage).toBe(true);
  const download = page.waitForEvent("download");
  await page.locator("[data-ui=licence-request]").click();
  const file = await download;
  expect(file.suggestedFilename()).toBe(`hawk-ai-${status.json.installationId}.hawkai-request`);
  await expect(page.locator("#licence-file")).toHaveAttribute("accept", ".hawkai");
  await page.locator("#licence-file").setInputFiles({ name: "not-a-licence.hawkai", mimeType: "application/octet-stream", buffer: Buffer.from("{}") });
  await page.getByRole("button", { name: "Upload .hawkai licence" }).click();
  await expect(page.locator("[data-ui=licence-upload] [role=status]")).toHaveText("This file is not a Hawk AI licence.");
  // Still in the trial: nothing changed.
  expect((await callApi(page, "GET", "/licence")).json.trial).toBe(true);
});

test("The deactivation page shows the installation ID and, signed in as the administrator, the upload, on a phone too", async ({ page }) => {
  // The trial has not ended here: the licence's answer is made to say so for this page only.
  await page.route(/\/api\/licence$/, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ active: false, until: "2026-11-28T12:00:00.000Z", trial: false, installationId: "HK-TEST-TEST-TEST-TEST", message: "The product has been deactivated. Please reach out to Bhawani Singh." }),
    }),
  );
  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto("/settings/activation");
  const screen = page.locator("[data-ui=licence-deactivated]");
  await expect(screen.getByRole("heading", { level: 1, name: "The product has been deactivated." })).toBeVisible();
  const status = await callApi(page, "GET", "/licence/status");
  await expect(screen.locator("[data-ui=installation-id] code")).toHaveText(status.json.installationId);
  await expect(screen.getByRole("button", { name: "Copy" })).toBeVisible();
  await expect(screen.locator("[data-ui=licence-request]")).toBeVisible();
  await expect(screen.getByRole("button", { name: "Upload .hawkai licence" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("One workspace: its owner is the server's administrator and changes the whole server's settings", async ({ page }) => {
  // The first workspace's owners and admins are the server's administrators (app/core/installation.py): with one
  // workspace nothing is read-only for them.
  const me = await callApi(page, "GET", "/settings/me");
  expect(me.status).toBe(200);
  expect(me.json.installationAdmin).toBe(true);
  await page.goto("/settings/signin");
  await expect(page.getByRole("heading", { level: 1, name: "Sign-in" })).toBeVisible();
  await expect(page.locator("input[name=minLength]")).toBeEnabled();
  await expect(page.locator("[data-ui=server-setting-note]")).toHaveCount(0);
  const compliance = await callApi(page, "GET", "/compliance");
  expect(compliance.status).toBe(200);
  expect(compliance.json.mayChange).toBe(true);
});
