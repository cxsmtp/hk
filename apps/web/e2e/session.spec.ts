import { ADMIN, callApi, expect, expectNoTokensInBrowserStorage, signIn, signOut, test } from "./support/fixtures";

/** The console's session in HttpOnly cookies (apps/api/app/core/session_cookies.py), as the browser sees it. */

test("the session survives a reload", async ({ page }) => {
  await signIn(page, ADMIN.email, ADMIN.password);
  await expect(page).toHaveURL(/\/dashboard\/command-center$/);
  await page.reload();
  await expect(page).toHaveURL(/\/dashboard\/command-center$/);
  await expect(page.getByRole("button", { name: "Account and administration" })).toContainText(ADMIN.email);
  const me = await callApi(page, "GET", "/auth/me");
  expect(me.status).toBe(200);
  expect(me.json.email).toBe(ADMIN.email);
  await expectNoTokensInBrowserStorage(page);
});

test("an expired access cookie is renewed with the refresh cookie under /api", async ({ page, watch }) => {
  // The first request without the access cookie is a 401; the console then refreshes and tries again.
  watch.allow(401, /^\/api\//);
  await signIn(page, ADMIN.email, ADMIN.password);
  const before = (await page.context().cookies()).find((c) => c.name === "hawk_access")?.value;
  await page.context().clearCookies({ name: "hawk_access" });
  const refreshed = page.waitForResponse((r) => r.url().endsWith("/api/auth/refresh") && r.request().method() === "POST");
  await page.goto("/settings/people");
  expect((await refreshed).status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "People", exact: true })).toBeVisible();
  const after = (await page.context().cookies()).find((c) => c.name === "hawk_access")?.value;
  expect(after).toBeTruthy();
  expect(after).not.toBe(before);
  await expectNoTokensInBrowserStorage(page);
});

test("signing out clears the session", async ({ page, watch }) => {
  watch.allow(401, /^\/api\//);
  await signIn(page, ADMIN.email, ADMIN.password);
  await expectNoTokensInBrowserStorage(page);
  await signOut(page);
  await expect(page.getByText("Enterprise Sign In")).toBeVisible();
  const names = (await page.context().cookies()).map((c) => c.name);
  expect(names).not.toContain("hawk_access");
  expect(names).not.toContain("hawk_refresh");
  expect(names).not.toContain("hawk_csrf");
  expect(await page.evaluate(() => window.localStorage.getItem("hawk-console-session"))).toBeNull();
  await expectNoTokensInBrowserStorage(page);
  // The API no longer knows this browser, and a console page sends it back to sign in.
  expect((await callApi(page, "GET", "/auth/me")).status).toBe(401);
  await page.goto("/settings/people");
  await page.waitForURL((url) => url.pathname.startsWith("/login"));
});

test("a state-changing request without the CSRF header is refused", async ({ page, watch }) => {
  watch.allow(403, /^\/api\/settings\/branding$/);
  await signIn(page, ADMIN.email, ADMIN.password);
  const before = await callApi(page, "GET", "/branding");
  expect(before.status).toBe(200);

  const refused = await callApi(page, "PUT", "/settings/branding", { tagline: "changed without csrf" }, { csrf: false });
  expect(refused.status).toBe(403);
  expect(JSON.stringify(refused.json)).toContain("CSRF");
  expect((await callApi(page, "GET", "/branding")).json.tagline).toBe(before.json.tagline);

  // A token that is not this session's is refused too.
  const forged = await page.evaluate(async () => {
    const response = await fetch("/api/settings/branding", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Hawk-Session": "cookie", "X-CSRF-Token": "forged-token" },
      body: JSON.stringify({ tagline: "changed with a forged csrf token" }),
    });
    return response.status;
  });
  expect(forged).toBe(403);

  // With the header the console sends, the same request is accepted.
  const accepted = await callApi(page, "PUT", "/settings/branding", { tagline: before.json.tagline || "AI control plane" });
  expect(accepted.status).toBe(200);
});
