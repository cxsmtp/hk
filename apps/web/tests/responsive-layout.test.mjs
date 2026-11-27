import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chooseLayout, columnNames, labelTable } from "../src/lib/responsive-tables.mjs";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

// A small stand-in for the DOM's tables: what labelTable reads and writes.
function cell(tagName, text, { colSpan = 1, label } = {}) {
  const attrs = new Map(label === undefined ? [] : [["data-label", label]]);
  return {
    tagName,
    textContent: text,
    colSpan,
    hasAttribute: (name) => attrs.has(name),
    getAttribute: (name) => (attrs.has(name) ? attrs.get(name) : null),
    setAttribute: (name, value) => attrs.set(name, value),
    removeAttribute: (name) => attrs.delete(name),
  };
}
function row(cells, parentElement = null) {
  const r = { cells, parentElement, ...cell("TR", "") };
  return r;
}
function table({ head, body, attrs = {} }) {
  const own = new Map(Object.entries(attrs));
  const tHead = head ? { rows: [] } : null;
  const t = {
    tHead,
    rows: [],
    hasAttribute: (name) => own.has(name),
    getAttribute: (name) => (own.has(name) ? own.get(name) : null),
    setAttribute: (name, value) => own.set(name, value),
    removeAttribute: (name) => own.delete(name),
  };
  if (head) {
    const h = row(head, tHead);
    tHead.rows.push(h);
    t.rows.push(h);
  }
  for (const cells of body) t.rows.push(row(cells, {}));
  return t;
}

test("each body cell is given its column's name, colspan counted", () => {
  const t = table({
    head: [cell("TH", " When "), cell("TH", "Who / using what", { colSpan: 2 }), cell("TH", "")],
    body: [
      [cell("TD", "today"), cell("TD", "Ana"), cell("TD", "Chrome"), cell("TD", "…")],
      [cell("TD", "Nothing yet", { colSpan: 4 })],
    ],
  });
  assert.deepEqual(columnNames(t).names, ["When", "Who / using what", "Who / using what", ""]);
  labelTable(t);
  assert.equal(t.getAttribute("data-cards"), "table");
  const [first, second, third, fourth] = t.rows[1].cells;
  assert.equal(first.getAttribute("data-label"), "When");
  assert.equal(second.getAttribute("data-label"), "Who / using what");
  assert.equal(third.getAttribute("data-label"), "Who / using what");
  assert.equal(fourth.hasAttribute("data-label"), false, "an unnamed column gets no label");
  assert.equal(t.rows[2].cells[0].getAttribute("data-label"), "When");
  // The header row is left alone.
  assert.equal(t.rows[0].cells[0].hasAttribute("data-label"), false);
});

test("a label the page set is kept, and a grid that must stay a grid is not made into cards", () => {
  const kept = table({ head: [cell("TH", "Name")], body: [[cell("TD", "x", { label: "Person" })]] });
  labelTable(kept);
  assert.equal(kept.rows[1].cells[0].getAttribute("data-label"), "Person");

  const grid = table({ head: [cell("TH", "Permission")], body: [[cell("TD", "x")]], attrs: { "data-table": "scroll", "data-cards": "" } });
  labelTable(grid);
  assert.equal(grid.hasAttribute("data-cards"), false);
  assert.equal(grid.rows[1].cells[0].hasAttribute("data-label"), false);
});

test("a table without a header row is still a list of cards on a phone, without labels", () => {
  const t = table({ body: [[cell("TD", "a"), cell("TD", "b")]] });
  labelTable(t);
  assert.equal(t.getAttribute("data-cards"), "table");
  assert.equal(t.rows[0].cells[0].hasAttribute("data-label"), false);
});

test("the console's frame: no sideways strips, a drawer menu, 100dvh and safe areas, 16 px fields", () => {
  const css = source("app/globals.css");
  for (const rule of [
    'table[data-cards="stack"]',
    "content: attr(data-label)",
    "min-height: 100dvh",
    "env(safe-area-inset-bottom)",
    "-webkit-backdrop-filter: blur(12px)",
    "font-size: 16px !important",
    ":where(.grid, .inline-grid) > *",
    "-webkit-text-size-adjust: 100%",
  ]) assert.ok(css.includes(rule), rule);

  const shell = source("components/app-shell.tsx");
  assert.match(shell, /<ResponsiveTables \/>/);
  assert.match(shell, /<Topbar leading=\{<MobileLifecycleNav \/>\} \/>/);

  const mobile = source("components/mobile-lifecycle-nav.tsx");
  assert.doesNotMatch(mobile, /overflow-x-auto/, "the phone menu never scrolls sideways");
  assert.match(mobile, /createPortal/);
  assert.match(mobile, /aria-label="Open the main menu"/);
  assert.match(mobile, /event\.key === "Escape"/);

  const layout = source("app/layout.tsx");
  assert.match(layout, /viewportFit: "cover"/);
  assert.match(layout, /width: "device-width"/);

  const settings = source("app/settings/ftr-settings.css");
  assert.ok(settings.includes(".ftr-settings .set-nav[data-open=\"true\"]"));
  assert.ok(settings.includes(".ftr-settings label.pack-select"));
});

test("browsers: the last two versions of Safari (macOS and iOS), Chrome, Edge and Firefox", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  for (const query of ["last 2 Chrome versions", "last 2 Edge versions", "last 2 Firefox versions", "last 2 Safari versions", "last 2 iOS versions"]) {
    assert.ok(pkg.browserslist.includes(query), query);
  }
});

test("the light look is the default, set before the page is drawn, and each browser can choose dark or system", () => {
  const layout = source("app/layout.tsx");
  assert.match(layout, /<html lang="en" data-theme="light"/);
  assert.match(layout, /dangerouslySetInnerHTML=\{\{ __html: THEME_BOOT \}\}/);
  const theme = source("lib/theme.ts");
  assert.match(theme, /export const THEME_KEY = "hawk-theme"/);
  // Without a choice of its own the browser shows the organisation's default, else light (never the device's).
  assert.match(theme, /resolveTheme\(isChoice\(organisationDefault\) \? organisationDefault : "light"\)/);
  assert.match(theme, /try \{\s*window\.localStorage\.setItem\(THEME_KEY, choice\)/);
  assert.match(source("lib/settings-console.ts"), /mode: "light"/);
  assert.match(source("lib/settings-console.ts"), /applyTheme\(currentTheme\(b\.mode\)\)/);
  const topbar = source("components/topbar.tsx");
  assert.match(topbar, /<ThemeSwitch \/>/);
  assert.match(topbar, /<WorkspaceSwitch \/>/);
  const sw = source("components/theme-switch.tsx");
  for (const label of ['"Light"', '"Dark"', '"System"']) assert.ok(sw.includes(label), label);
  const css = source("app/globals.css");
  assert.ok(css.includes('@import "../styles/light-theme.generated.css";'));
  assert.ok(css.includes(':root:not([data-theme="light"]) .text-slate-500'), "the dark look's own remaps stay dark-only");
  assert.ok(source("styles/theme.css").includes(':root[data-theme="light"] {'));
});

test("the generated light look is up to date with the colour classes the pages use", () => {
  const run = spawnSync(process.execPath, [fileURLToPath(new URL("../scripts/gen-light-theme.mjs", import.meta.url)), "--check"], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const css = source("styles/light-theme.generated.css");
  // Dark surfaces white, light text dark, faint white lines faint dark ones, dark tints light ones, readable colour text.
  assert.ok(css.includes(':root[data-theme="light"] .bg-\\[\\#0f1218\\] { background-color: #ffffff; }'));
  assert.ok(css.includes(':root[data-theme="light"] .bg-red-950\\/40 { background-color: #fef2f2; }'));
  assert.match(css, /:root\[data-theme="light"\] \.text-slate-300(:not\([^)]*\))? \{ color: #1e293b; \}/);
  assert.match(css, /:root\[data-theme="light"\] \.text-orange-200(:not\([^)]*\))? \{ color: #9a3412; \}/);
  // White text on a solid coloured button stays white.
  assert.match(css, /\.text-white:not\(\.bg-red-500, /);
});

test("a table stays a table only where it fits its box, and is always cards on a phone", () => {
  const t = table({ head: [cell("TH", "Name")], body: [[cell("TD", "x")]] });
  labelTable(t);
  let natural = 900;
  Object.defineProperty(t, "offsetWidth", { get: () => (t.getAttribute("data-cards") === "table" ? natural : 600) });
  t.parentElement = { clientWidth: 700 };
  chooseLayout(t, 1280);
  assert.equal(t.getAttribute("data-cards"), "stack", "900 px of table in a 700 px box: cards");
  natural = 650;
  chooseLayout(t, 1280);
  assert.equal(t.getAttribute("data-cards"), "table", "it fits again: a table");
  chooseLayout(t, 390);
  assert.equal(t.getAttribute("data-cards"), "stack", "a phone: cards");
  const grid = table({ head: [cell("TH", "Permission")], body: [[cell("TD", "x")]], attrs: { "data-table": "scroll" } });
  labelTable(grid);
  chooseLayout(grid, 390);
  assert.equal(grid.hasAttribute("data-cards"), false, "a grid that must stay a grid is never made into cards");
});
