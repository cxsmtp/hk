import { expect, test, type Page } from "@playwright/test";

import { ADMIN, signIn } from "./support/fixtures";
import { measureLayout } from "./support/layout";
import { CONSOLE_ROUTES, PUBLIC_ROUTES } from "./support/routes";

/**
 * Every page fits the window: at a phone's width (360), a tablet's (768) and a laptop's (1280) nothing makes the page
 * scroll sideways, nothing runs past the window's edge or is cut off by the console's frame, and no box inside the page
 * scrolls sideways either (wide tables become cards): only a grid that must stay a grid (table[data-table=scroll],
 * the permission matrix) or preformatted text may.
 *
 * One sign-in for the whole run; each page is opened once and the window is resized around it. Runs in Chromium with
 * the rest of the suite, and in WebKit (Safari) and Firefox too when E2E_EXTRA_BROWSERS names them (playwright.config).
 */

const WIDTHS = [360, 768, 1280];
const HEIGHT = 820;

async function settle(page: Page): Promise<void> {
  await page.waitForLoadState("load").catch(() => undefined);
  await page.locator("h1").first().waitFor({ timeout: 8_000 }).catch(() => undefined);
  await page.waitForTimeout(500);
}

async function checkWidths(page: Page, route: string, problems: string[]): Promise<void> {
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: HEIGHT });
    await page.waitForTimeout(250);
    const report = await measureLayout(page);
    if (report.pageOverflow > 0 || report.offenders.length) {
      const where = report.offenders.slice(0, 3).map((o) => `${o.selector} [${o.left}..${o.right}] "${o.text}"`).join("; ");
      problems.push(`${route} at ${width}px: the page is ${report.pageOverflow}px wider than the window${where ? `; past the edge: ${where}` : ""}`);
    }
    // Nor a box inside the page that scrolls sideways, but for a grid that must stay a grid or preformatted text.
    for (const box of report.sideScrollers.filter((b) => !b.intended)) {
      problems.push(`${route} at ${width}px: ${box.selector} scrolls sideways (${box.scrollWidth}px in ${box.clientWidth}px)`);
    }
  }
}

async function visit(page: Page, route: string, problems: string[]): Promise<void> {
  await page.setViewportSize({ width: WIDTHS[0], height: HEIGHT });
  await page.goto(route, { waitUntil: "domcontentloaded" });
  await settle(page);
  await checkWidths(page, route, problems);
}

test("no page scrolls sideways or runs off the screen, from a phone to a laptop", async ({ page }) => {
  test.setTimeout(20 * 60_000);
  const problems: string[] = [];

  for (const route of PUBLIC_ROUTES) await visit(page, route, problems);

  await signIn(page, ADMIN.email, ADMIN.password);
  for (const route of CONSOLE_ROUTES) await visit(page, route, problems);

  expect(problems, "pages wider than the window").toEqual([]);
});

test("on a phone the main menu is a drawer and Settings' menu folds into one button", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  // Fields are at least 16 px, so iOS Safari does not zoom into them.
  await page.goto("/login");
  const size = await page.locator("input[autocomplete=username]").evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
  expect(size).toBeGreaterThanOrEqual(16);

  await signIn(page, ADMIN.email, ADMIN.password);
  await page.goto("/settings/people");
  await expect(page.getByRole("heading", { level: 1, name: "People", exact: true })).toBeVisible();

  // The desktop side menu is not shown; the menu button opens the drawer, listing the areas one under the other.
  await expect(page.locator("aside[aria-label='Primary navigation']")).toBeHidden();
  const menu = page.getByRole("button", { name: "Open the main menu" });
  await menu.click();
  const drawer = page.getByRole("dialog", { name: "Main menu" });
  await expect(drawer).toBeVisible();
  const areas = drawer.getByRole("navigation", { name: "Mobile lifecycle navigation" });
  await expect(areas.getByRole("link", { name: /Inventory/ })).toBeVisible();
  // Once it has slid in, it is inside the window.
  await expect.poll(async () => Math.round((await drawer.boundingBox())?.x ?? -1)).toBe(0);
  const box = await drawer.boundingBox();
  expect(box && box.x + box.width <= 390).toBe(true);
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  // Settings' own menu: one button naming the page open, which opens the list.
  const toggle = page.locator(".set-toggle");
  await expect(toggle).toBeVisible();
  await expect(toggle).toContainText("People");
  const nav = page.getByRole("navigation", { name: "Settings" });
  await expect(nav).toBeHidden();
  await toggle.click();
  await expect(nav).toBeVisible();
  await expect(nav.getByRole("link", { name: "Teams", exact: true })).toBeVisible();

  // Tables are cards on a phone: no header row shown, each cell with its column's name.
  const table = page.locator("table[data-cards=stack]").first();
  if (await table.count()) {
    await expect(table.locator("thead")).toHaveCSS("position", "absolute");
    const labelled = await table.locator("td[data-label]").count();
    expect(labelled).toBeGreaterThan(0);
  }

});
