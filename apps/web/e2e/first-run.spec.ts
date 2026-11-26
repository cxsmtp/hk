import { ADMIN, acceptTerms, changeTemporaryPassword, expect, expectNoTokensInBrowserStorage, test } from "./support/fixtures";

/**
 * A new installation, as deploy/compose.yaml starts one: the API made the first administrator from ADMIN_EMAIL and
 * ADMIN_PASSWORD (a temporary password), and nobody has accepted the terms of use. These run first (the "first-run"
 * project); every other test signs in with the password chosen here.
 */
test.describe.configure({ mode: "serial" });

test("the sign-in page renders", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByText("Enterprise Sign In")).toBeVisible();
  await expect(page.locator("input[autocomplete=username]")).toBeVisible();
  await expect(page.locator("input[autocomplete=current-password]")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign In", exact: true })).toBeEnabled();
  await expect(page.locator("[data-ui=onprem-note]")).toContainText("Runs on your own servers");
  await expectNoTokensInBrowserStorage(page);
});

test("a wrong password is refused with a message", async ({ page, watch }) => {
  watch.allow(401, /^\/api\/auth\/login$/);
  await page.goto("/login");
  await page.locator("input[autocomplete=username]").fill(ADMIN.email);
  await page.locator("input[autocomplete=current-password]").fill("not-the-right-password-2026");
  const answer = page.waitForResponse((r) => r.url().endsWith("/api/auth/login"));
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  expect((await answer).status()).toBe(401);
  const status = page.locator("[data-ui=login-status]");
  await expect(status).toBeVisible();
  await expect(status).toContainText(/wrong|incorrect|invalid/i);
  await expect(page).toHaveURL(/\/login$/);
  expect((await page.context().cookies()).map((c) => c.name)).not.toContain("hawk_access");
  await expectNoTokensInBrowserStorage(page);
});

test("first sign-in: forced password change, then the terms of use, then the dashboard", async ({ page, watch }) => {
  // Until the password is changed and the terms accepted, the API says so with a 403 the console turns into a page.
  watch.allow(403, /^\/api\//);
  await page.goto("/login");
  await page.locator("input[autocomplete=username]").fill(ADMIN.email);
  await page.locator("input[autocomplete=current-password]").fill(ADMIN.temporaryPassword);
  const login = page.waitForResponse((r) => r.url().endsWith("/api/auth/login"));
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  const answer = await login;
  expect(answer.status()).toBe(200);
  const body = await answer.json();
  // The console's sign-in: tokens as HttpOnly cookies, never in the body a script could read.
  expect(body.access_token).toBe("");
  expect(body.refresh_token).toBe("");
  expect(body.must_change_password).toBe(true);
  const cookies = await page.context().cookies();
  const access = cookies.find((c) => c.name === "hawk_access");
  const refresh = cookies.find((c) => c.name === "hawk_refresh");
  expect(access?.httpOnly).toBe(true);
  expect(access?.sameSite).toBe("Strict");
  expect(refresh?.httpOnly).toBe(true);
  // X-Forwarded-Prefix from the front proxy: the refresh cookie goes to the refresh path under /api only.
  expect(refresh?.path).toBe("/api/auth/refresh");
  expect(cookies.find((c) => c.name === "hawk_csrf")?.httpOnly).toBe(false);
  await expectNoTokensInBrowserStorage(page);

  await changeTemporaryPassword(page, ADMIN.temporaryPassword, ADMIN.password);
  await expectNoTokensInBrowserStorage(page);

  await acceptTerms(page);
  await expectNoTokensInBrowserStorage(page);

  await expect(page).toHaveURL(/\/dashboard\/command-center$/);
  await expect(page.getByRole("button", { name: "Account and administration" })).toContainText(ADMIN.email);
  await expect(page.getByText("Top actions now")).toBeVisible();
  await expectNoTokensInBrowserStorage(page);
});
