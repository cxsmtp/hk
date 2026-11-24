import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/components/detail-drawer.tsx", import.meta.url), "utf8");

test("detail drawer is a labelled modal dialog", () => {
  assert.match(source, /role="dialog"/);
  assert.match(source, /aria-modal="true"/);
  assert.match(source, /aria-labelledby=\{titleId\}/);
  assert.match(source, /aria-describedby=\{subtitle \? subtitleId : undefined\}/);
});

test("detail drawer supports keyboard dismissal and focus containment", () => {
  assert.match(source, /event\.key === "Escape"/);
  assert.match(source, /event\.key === "Tab"/);
  assert.match(source, /previousFocusRef/);
  assert.match(source, /closeButtonRef/);
  assert.match(source, /previousFocusRef\.current\?\.focus/);
});

test("detail drawer preserves the page and mobile investigation context", () => {
  assert.match(source, /document\.body\.style\.overflow = "hidden"/);
  assert.match(source, /max-w-2xl/);
  assert.match(source, /aria-label="Close investigation"/);
});

test("detail drawer supports a wide policy-composer surface without changing its default", () => {
  assert.match(source, /size\?: "default" \| "wide"/);
  assert.match(source, /size = "default"/);
  assert.match(source, /size === "wide"/);
  assert.match(source, /max-w-5xl/);
});
