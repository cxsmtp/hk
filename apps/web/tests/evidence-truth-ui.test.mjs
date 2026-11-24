import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const truthPanel = readFileSync(
  new URL("../src/components/evidence/evidence-truth-panel.tsx", import.meta.url),
  "utf8",
);
const aiTools = readFileSync(new URL("../src/app/ai-tools-usage/page.tsx", import.meta.url), "utf8");
const ecosystem = readFileSync(
  new URL("../src/components/ecosystem/ai-ecosystem-workspace.tsx", import.meta.url),
  "utf8",
);
const surfaceCoverage = readFileSync(new URL("../src/app/surface-coverage/page.tsx", import.meta.url), "utf8");
const github = readFileSync(
  new URL("../src/app/control-coverage/source-control/github-repository-boundary/page.tsx", import.meta.url),
  "utf8",
);
const unknownAI = readFileSync(
  new URL("../src/components/discovery/discovery-unknown-ai.tsx", import.meta.url),
  "utf8",
);
const validateWorkspace = readFileSync(
  new URL("../src/components/lifecycle/validate-workspace.tsx", import.meta.url),
  "utf8",
);

test("shared evidence truth panel exposes the required plain-language controls", () => {
  for (const phrase of [
    "Why unknown?",
    "Last evidence received",
    "Connect source",
    "Test this control now",
    "Demo / proof data",
    "Authoritative production source",
    "Browser-observed, provider-native verified",
    "estimated",
  ]) {
    assert.match(truthPanel, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
});

test("other high-risk pages embed evidence truth guidance instead of bare Unknown states", () => {
  for (const [name, source] of [
    ["AI Tools & Usage", aiTools],
    ["AI Ecosystem", ecosystem],
    ["Surface Coverage", surfaceCoverage],
  ]) {
    assert.match(source, /EvidenceTruthPanel/, `${name} should use the shared evidence panel`);
  }
});

test("AI Tools & Usage explains account, provider, model, token and spend provenance", () => {
  for (const phrase of [
    "Provider/model seen from browser",
    "Provider-native verified",
    "Personal vs enterprise account",
    "Token/spend provenance",
    "Billed, provider-reported, rate-card, client-estimated and unavailable states stay separate",
    "Observed provider activity",
    "Provider-native connector",
    "Observed MCP activity",
    "Normalized MCP inventory",
    "Client-estimated usage",
  ]) {
    assert.match(aiTools, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
});

test("GitHub Access & AI keeps evidence and freshness boundaries in connection details", () => {
  for (const phrase of [
    "Connection details and test tools",
    "Evidence and freshness",
    "Last selected repository evidence",
    "Missing or stale evidence stays unknown",
    "Not allowed by this draft",
    "No AI tool calls are available",
  ]) {
    assert.match(github, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
});

test("Unknown AI and Validate pages provide actionable non-empty demo states", () => {
  for (const phrase of [
    "Review evidence",
    "Connect source",
    "Run bounded scan",
    "Resolve selected unknown",
    "Investigation queue",
  ]) {
    assert.match(unknownAI, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
  for (const phrase of [
    "Control Test Center",
    "Run one safe test and show the result",
    "Browser prompt injection",
    "GitHub repo boundary",
    "MCP tool action",
    "Endpoint command",
    "/simulations",
    "Simulation catalog",
    "Run first control test",
    "Coverage impact",
    "Control test results",
  ]) {
    assert.match(validateWorkspace, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
});
