import { expect, test as base, type Page } from "@playwright/test";

import { ADMIN } from "./accounts";

export { ADMIN };

/**
 * What every browser test shares: the throwaway installation's accounts, signing in through the real sign-in page,
 * and a watch on the page that fails the test on a console error, an uncaught exception or an error answer (4xx/5xx)
 * from this origin that the test did not say it expects.
 */

type Allowed = { status: number | RegExp; path: RegExp };

export type Watch = {
  /** An error answer this test expects (status, and a pattern for the path, /api included). */
  allow: (status: number | RegExp, path: RegExp) => void;
  /** Everything unexpected seen so far. */
  problems: () => string[];
};

function matches(rule: Allowed, status: number, path: string): boolean {
  const statusOk = typeof rule.status === "number" ? rule.status === status : rule.status.test(String(status));
  return statusOk && rule.path.test(path);
}

export const test = base.extend<{ watch: Watch }>({
  watch: [
    async ({ page, baseURL }, use) => {
      const origin = new URL(baseURL || "http://127.0.0.1").origin;
      const allowed: Allowed[] = [];
      const problems: string[] = [];
      page.on("pageerror", (error) => problems.push(`uncaught exception: ${error.message}`));
      page.on("console", (message) => {
        if (message.type() !== "error") return;
        // Chrome's own line for an error answer: judged by the response below, with its path and the allow list.
        if (/^Failed to load resource: the server responded with a status of \d+/.test(message.text())) return;
        problems.push(`console error: ${message.text()}`);
      });
      page.on("response", (response) => {
        const url = new URL(response.url());
        if (url.origin !== origin || response.status() < 400) return;
        const status = response.status();
        if (allowed.some((rule) => matches(rule, status, url.pathname))) return;
        problems.push(`${status} ${response.request().method()} ${url.pathname}`);
      });
      await use({ allow: (status, path) => allowed.push({ status, path }), problems: () => [...problems] });
      expect(problems, "console errors, uncaught exceptions or unexpected error answers").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/**
 * Sign in on the sign-in page; returns once the console has left /login. The API allows 30 sign-in attempts per
 * address in 10 minutes (apps/api/app/services/account_security.py) and every test comes from 127.0.0.1: the whole
 * suite uses about half of that, so keep new tests to one sign-in each.
 */
export async function signIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto("/login");
  await expect(page.getByText("Enterprise Sign In")).toBeVisible();
  await page.locator("input[autocomplete=username]").fill(email);
  await page.locator("input[autocomplete=current-password]").fill(password);
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"));
  await expectNoTokensInBrowserStorage(page);
}

/** Sign out from the account menu at the top of every console page. */
export async function signOut(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Account and administration" }).click();
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL((url) => url.pathname.startsWith("/login"));
}

/** Choose a new password on the forced change-password screen of a first sign-in. */
export async function changeTemporaryPassword(page: Page, current: string, next: string): Promise<void> {
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  await page.locator("#change-current").fill(current);
  await page.locator("#change-next").fill(next);
  await page.locator("#change-next2").fill(next);
  await page.getByRole("button", { name: "Save password" }).click();
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeHidden();
}

/** Read the terms of use to the end, tick, and accept (naming the organisation when asked). */
export async function acceptTerms(page: Page, organisation = ADMIN.organisation): Promise<void> {
  await expect(page.getByRole("heading", { name: /^Terms of use · version / })).toBeVisible();
  const text = page.locator(".terms-text");
  await expect(text).not.toContainText("Loading…");
  await text.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    element.dispatchEvent(new Event("scroll"));
  });
  const organisationName = page.locator("#terms-org");
  if (await organisationName.isVisible()) await organisationName.fill(organisation);
  const box = page.getByRole("checkbox");
  await expect(box).toBeEnabled();
  await box.check();
  await page.getByRole("button", { name: "Accept and continue" }).click();
  await expect(page.locator("[data-ui=access-gate]")).toBeHidden();
}

/**
 * The sign-in lives in HttpOnly cookies only: nothing in localStorage or sessionStorage holds a token, under any key,
 * and none of the session cookies' values appears there.
 */
export async function expectNoTokensInBrowserStorage(page: Page): Promise<void> {
  const cookies = await page.context().cookies();
  const secrets = cookies.filter((c) => /hawk_(access|refresh)$/.test(c.name)).map((c) => c.value).filter(Boolean);
  const stored = await page.evaluate(() => {
    const all: Array<[string, string]> = [];
    for (const storage of [window.localStorage, window.sessionStorage]) {
      for (let i = 0; i < storage.length; i += 1) {
        const key = storage.key(i) || "";
        all.push([key, storage.getItem(key) || ""]);
      }
    }
    return all;
  });
  for (const [key, value] of stored) {
    expect(key, "no token-like key in browser storage").not.toMatch(/token|ai-control-plane-session/i);
    expect(value, `no token in browser storage (${key})`).not.toMatch(/access_token|refresh_token|eyJ[A-Za-z0-9_-]{10,}\.eyJ/);
    for (const secret of secrets) expect(value.includes(secret), `a session cookie's value in browser storage (${key})`).toBe(false);
  }
}

/**
 * A request to the API from inside the page, as the console makes it: same origin, the session cookies, the
 * X-Hawk-Session header, and the CSRF token from its cookie unless `csrf` is false.
 */
export async function callApi(
  page: Page,
  method: string,
  path: string,
  body?: unknown,
  { csrf = true }: { csrf?: boolean } = {},
): Promise<{ status: number; json: any }> {
  return page.evaluate(
    async ({ method, path, body, csrf }) => {
      const headers: Record<string, string> = { "X-Hawk-Session": "cookie", Accept: "application/json" };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      // The tenant the console signed in to (only who is signed in is kept in localStorage, never a token).
      try {
        const session = JSON.parse(window.localStorage.getItem("hawk-console-session") || "null");
        if (session?.tenantId) headers["X-Tenant-ID"] = session.tenantId;
      } catch {
        // No session kept: the request goes without a tenant.
      }
      if (csrf) {
        const found = document.cookie.split(";").map((p) => p.trim()).find((p) => p.startsWith("hawk_csrf=") || p.startsWith("__Host-hawk_csrf="));
        if (found) headers["X-CSRF-Token"] = decodeURIComponent(found.slice(found.indexOf("=") + 1));
      }
      const response = await fetch(`/api${path}`, {
        method,
        headers,
        credentials: "same-origin",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      let json: unknown = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = text;
      }
      return { status: response.status, json };
    },
    { method, path, body, csrf },
  );
}
