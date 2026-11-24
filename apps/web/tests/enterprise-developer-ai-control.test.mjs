import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const pagePath = new URL("../src/app/control-coverage/source-control/github-repository-boundary/page.tsx", import.meta.url);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const nav = readFileSync(new URL("../src/lib/navigation.ts", import.meta.url), "utf8");

test("GitHub Access and AI is a first-class customer control route", () => {
  assert.equal(existsSync(pagePath), true);
  const page = readFileSync(pagePath, "utf8");
  assert.match(page, /GitHub access &amp; AI controls/);
  assert.match(page, /Connect GitHub/);
  assert.match(page, /Choose repositories/);
  assert.match(page, /Define controls/);
  assert.match(page, /Recent activity/);
  assert.match(page, /Unauthorized repository attempts/);
  assert.match(page, /AI tool coverage for this repository/);
  assert.match(page, /Unsupported paths stay visible/);
  assert.doesNotMatch(page, /productivity score/i);
  assert.doesNotMatch(page, /raw prompt/i);
});

test("web API exposes the customer package without unsafe mutations", () => {
  assert.match(api, /enterpriseDeveloperAIControl/);
  assert.match(api, /\/control-coverage\/source-control\/github-repository-boundary/);
  assert.doesNotMatch(api, /enterpriseDeveloperAIControl:[^\n]*method:\s*["']POST/s);
});

test("navigation links Source Control boundary under Deploy coverage", () => {
  assert.match(nav, /label: "GitHub"/);
  assert.match(nav, /\/control-coverage\/source-control\/github-repository-boundary/);
});
