import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const pageHeader = readFileSync(new URL("../src/components/page-header.tsx", import.meta.url), "utf8");
const kpiStrip = readFileSync(new URL("../src/components/kpi-strip.tsx", import.meta.url), "utf8");
const pageSection = readFileSync(new URL("../src/components/page-section.tsx", import.meta.url), "utf8");
const workspaceHeader = readFileSync(new URL("../src/components/lifecycle/workspace-header.tsx", import.meta.url), "utf8");
const workspaceLinks = readFileSync(new URL("../src/components/lifecycle/workspace-links.tsx", import.meta.url), "utf8");

test("shared page headers use one compact operational hierarchy", () => {
  assert.match(pageHeader, /data-ui="operational-page-header"/);
  assert.match(workspaceHeader, /data-ui="workspace-header"/);
  assert.match(workspaceHeader, /border-b/);
  assert.doesNotMatch(workspaceHeader, /blur-3xl|bg-gradient-to-r/);
});

test("metrics render as one connected evidence strip", () => {
  assert.match(kpiStrip, /data-ui="connected-kpi-strip"/);
  assert.match(kpiStrip, /divide-y/);
  assert.match(kpiStrip, /CircleHelp/);
  assert.doesNotMatch(kpiStrip, /<svg/);
});

test("sections and specialist links use flat progressive disclosure", () => {
  assert.match(pageSection, /data-ui="operational-section"/);
  assert.match(pageSection, /border-b/);
  assert.doesNotMatch(pageSection, /<Card/);
  assert.match(workspaceLinks, /<details/);
  assert.match(workspaceLinks, /<summary/);
  assert.match(workspaceLinks, /data-ui="specialist-links"/);
});

