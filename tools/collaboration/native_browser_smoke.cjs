// Synthetic seeded fixture only. Fresh browser profile; no installed extensions.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '../..');
const { chromium } = createRequire(path.join(root, 'extension/package.json'))('playwright');
const [api, web, output] = process.argv.slice(2);
for (const value of [api, web]) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port) {
    throw new Error('Browser fixtures require explicit task-owned loopback origins');
  }
}
const result = { api, web, passed: false, routes: [], browser_errors: [], api_errors: [] };
let browser;
(async () => {
  try {
    browser = await chromium.launch({headless: true,
      ...(process.env.HAWK_BROWSER_EXECUTABLE ? {executablePath: process.env.HAWK_BROWSER_EXECUTABLE} : {})});
    const page = await browser.newPage();
    page.on('pageerror', e => result.browser_errors.push(e.message));
    page.on('response', r => {
      if (new URL(r.url()).origin === api && r.status() >= 500) {
        result.api_errors.push({path: new URL(r.url()).pathname, status: r.status()});
      }
    });
    await page.goto(web + '/login', {waitUntil: 'domcontentloaded'});
    // These are public seed_e2e_fixtures values, never operator credentials.
    await page.locator('form input').nth(1).fill('owner@acme.ai');
    await page.locator('input[type=password]').fill('Password123!');
    const login = page.waitForResponse(r => r.url().startsWith(api + '/auth/login'));
    await page.getByRole('button', {name: 'Sign In', exact: true}).click();
    const response = await login;
    result.login_status = response.status();
    if (!response.ok()) throw new Error('Synthetic fixture login failed');
    await page.waitForURL(url => !url.pathname.startsWith('/login'), {timeout: 20000});
    for (const route of ['/dashboard/command-center', '/discovery/estate', '/protect', '/deploy',
                         '/surface-coverage', '/evidence', '/integrations', '/monitoring']) {
      const response = await page.goto(web + route, {waitUntil: 'domcontentloaded'});
      await page.locator('main').waitFor({state: 'visible'});
      await page.waitForTimeout(2000); // SSE prevents global network-idle readiness.
      const item = {route, status: response.status(), destination: new URL(page.url()).pathname,
                    body_length: (await page.locator('body').innerText()).length};
      result.routes.push(item);
      if (item.status !== 200 || item.destination !== route || item.body_length < 100) {
        throw new Error(`Route smoke failed: ${route}`);
      }
    }
    if (result.browser_errors.length || result.api_errors.length) throw new Error('Browser/API errors observed');
    await page.screenshot({path: path.join(output, 'native-browser.png'), fullPage: false});
    result.passed = true;
  } catch (error) {
    result.error = error.message;
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
    fs.writeFileSync(path.join(output, 'native-browser.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result, null, 2));
  }
})();
