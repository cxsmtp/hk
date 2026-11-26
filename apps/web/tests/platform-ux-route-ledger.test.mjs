import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const appRoot = new URL("../src/app/", import.meta.url);
const appRootPath = fileURLToPath(appRoot);
const ledgerPath = new URL("../../../docs/audits/2026-09-28-platform-ux/route-ledger.json", import.meta.url);

function pageRoutes(directory) {
  const routes = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name.startsWith("._")) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      routes.push(...pageRoutes(path));
      continue;
    }
    if (entry.name !== "page.tsx") continue;
    const routeParts = relative(appRootPath, path)
      .split(sep)
      .slice(0, -1)
      .filter((part) => !/^\(.+\)$/.test(part));
    routes.push(`/${routeParts.join("/")}`.replace(/\/$/, "") || "/");
  }
  return routes.sort();
}

const ledger = JSON.parse(readFileSync(ledgerPath, "utf8"));

test("route ledger exactly covers registered page routes", () => {
  const actualRoutes = pageRoutes(appRootPath);
  const ledgerRoutes = ledger.map((entry) => entry.route).sort();
  assert.equal(actualRoutes.length, 91, "the registered page route count changed");
  assert.deepEqual(ledgerRoutes, actualRoutes);
  assert.equal(new Set(ledgerRoutes).size, ledgerRoutes.length, "route ledger contains duplicates");
});

test("route ledger uses truthful completion vocabulary and no pending values", () => {
  const implementationStates = new Set(["updated", "source-reviewed", "blocked", "not-applicable"]);
  const automatedStates = new Set(["passed", "failed", "not-observed", "not-applicable"]);
  const browserStates = new Set(["observed", "blocked", "not-observed", "not-applicable"]);
  const stateStates = new Set(["observed", "not-observed", "not-applicable"]);

  for (const entry of ledger) {
    assert.ok(implementationStates.has(entry.implementation), `${entry.route}: invalid implementation state`);
    assert.ok(automatedStates.has(entry.automated), `${entry.route}: invalid automated state`);
    assert.ok(browserStates.has(entry.browser), `${entry.route}: invalid browser state`);
    assert.deepEqual(Object.keys(entry.states).sort(), ["loading", "ready-empty", "ready-populated", "stale", "unavailable"]);
    for (const [state, value] of Object.entries(entry.states)) {
      assert.ok(stateStates.has(value), `${entry.route} ${state}: invalid evidence state`);
    }
    assert.notEqual(entry.implementation, "pending");
    assert.notEqual(entry.automated, "pending");
    assert.notEqual(entry.browser, "pending");
    for (const value of Object.values(entry.states)) assert.notEqual(value, "pending");

    for (const view of entry.local_views) {
      assert.equal(typeof view.label, "string");
      assert.ok(browserStates.has(view.desktop), `${entry.route}/${view.label}: invalid desktop state`);
      assert.ok(browserStates.has(view.mobile), `${entry.route}/${view.label}: invalid mobile state`);
      assert.equal(typeof view.notes, "string");
    }
  }
});
