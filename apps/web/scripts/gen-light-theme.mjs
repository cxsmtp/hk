#!/usr/bin/env node
// The console's light look (src/styles/light-theme.generated.css), made from the colour classes the pages use.
//
// The pages are written for the dark look, with Tailwind colour classes (bg-[#0f1218], text-slate-300,
// border-white/[0.07], text-orange-200 …). This reads every class of that kind in src/ and writes, for each, what it
// becomes under :root[data-theme="light"]: dark surfaces become white or a very light grey, light text dark, faint
// white lines faint dark ones, and coloured tints on dark (red-950/40) their light counterparts (red-50), with
// coloured text dark enough to read on white (WCAG AA). Run it after adding colour classes:
//
//   node scripts/gen-light-theme.mjs           write the file
//   node scripts/gen-light-theme.mjs --check   fail if the file is out of date (tests/responsive-layout.test.mjs)

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL("..", import.meta.url));
const src = join(web, "src");
const out = join(src, "styles", "light-theme.generated.css");

const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950];
const PALETTE = Object.fromEntries(
  Object.entries({
    slate: "f8fafc f1f5f9 e2e8f0 cbd5e1 94a3b8 64748b 475569 334155 1e293b 0f172a 020617",
    gray: "f9fafb f3f4f6 e5e7eb d1d5db 9ca3af 6b7280 4b5563 374151 1f2937 111827 030712",
    zinc: "fafafa f4f4f5 e4e4e7 d4d4d8 a1a1aa 71717a 52525b 3f3f46 27272a 18181b 09090b",
    neutral: "fafafa f5f5f5 e5e5e5 d4d4d4 a3a3a3 737373 525252 404040 262626 171717 0a0a0a",
    stone: "fafaf9 f5f5f4 e7e5e4 d6d3d1 a8a29e 78716c 57534e 44403c 292524 1c1917 0c0a09",
    red: "fef2f2 fee2e2 fecaca fca5a5 f87171 ef4444 dc2626 b91c1c 991b1b 7f1d1d 450a0a",
    orange: "fff7ed ffedd5 fed7aa fdba74 fb923c f97316 ea580c c2410c 9a3412 7c2d12 431407",
    amber: "fffbeb fef3c7 fde68a fcd34d fbbf24 f59e0b d97706 b45309 92400e 78350f 451a03",
    yellow: "fefce8 fef9c3 fef08a fde047 facc15 eab308 ca8a04 a16207 854d0e 713f12 422006",
    lime: "f7fee7 ecfccb d9f99d bef264 a3e635 84cc16 65a30d 4d7c0f 3f6212 365314 1a2e05",
    green: "f0fdf4 dcfce7 bbf7d0 86efac 4ade80 22c55e 16a34a 15803d 166534 14532d 052e16",
    emerald: "ecfdf5 d1fae5 a7f3d0 6ee7b7 34d399 10b981 059669 047857 065f46 064e3b 022c22",
    teal: "f0fdfa ccfbf1 99f6e4 5eead4 2dd4bf 14b8a6 0d9488 0f766e 115e59 134e4a 042f2e",
    cyan: "ecfeff cffafe a5f3fc 67e8f9 22d3ee 06b6d4 0891b2 0e7490 155e75 164e63 083344",
    sky: "f0f9ff e0f2fe bae6fd 7dd3fc 38bdf8 0ea5e9 0284c7 0369a1 075985 0c4a6e 082f49",
    blue: "eff6ff dbeafe bfdbfe 93c5fd 60a5fa 3b82f6 2563eb 1d4ed8 1e40af 1e3a8a 172554",
    indigo: "eef2ff e0e7ff c7d2fe a5b4fc 818cf8 6366f1 4f46e5 4338ca 3730a3 312e81 1e1b4b",
    violet: "f5f3ff ede9fe ddd6fe c4b5fd a78bfa 8b5cf6 7c3aed 6d28d9 5b21b6 4c1d95 2e1065",
    purple: "faf5ff f3e8ff e9d5ff d8b4fe c084fc a855f7 9333ea 7e22ce 6b21a8 581c87 3b0764",
    fuchsia: "fdf4ff fae8ff f5d0fe f0abfc e879f9 d946ef c026d3 a21caf 86198f 701a75 4a044e",
    pink: "fdf2f8 fce7f3 fbcfe8 f9a8d4 f472b6 ec4899 db2777 be185d 9d174d 831843 500724",
    rose: "fff1f2 ffe4e6 fecdd3 fda4af fb7185 f43f5e e11d48 be123c 9f1239 881337 4c0519",
    // tailwind.config.ts: the brand scale is Tailwind's orange.
    brand: "fff7ed ffedd5 fed7aa fdba74 fb923c f97316 ea580c c2410c 9a3412 7c2d12 431407",
  }).map(([name, list]) => [name, Object.fromEntries(list.split(" ").map((hex, i) => [SHADES[i], `#${hex}`]))]),
);
const NEUTRAL = new Set(["slate", "gray", "zinc", "neutral", "stone"]);
const SCREENS = { sm: 640, md: 768, lg: 1024, xl: 1280, "2xl": 1536 };
const PSEUDO = {
  hover: ":hover",
  focus: ":focus",
  "focus-visible": ":focus-visible",
  "focus-within": ":focus-within",
  active: ":active",
  disabled: ":disabled",
  first: ":first-child",
  last: ":last-child",
  odd: ":nth-child(odd)",
  even: ":nth-child(even)",
};

// ---- colours -------------------------------------------------------------------------------------------------------
const hexToRgb = (hex) => {
  let h = hex.replace("#", "");
  if (h.length === 3 || h.length === 4) h = [...h].map((c) => c + c).join("");
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
};
const rgbToHex = (rgb) => `#${rgb.map((v) => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, "0")).join("")}`;
const luminance = ([r, g, b]) => {
  const lin = (v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
};
function rgbToHsl([r, g, b]) {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  const l = (max + min) / 2;
  if (max === min) return [0, 0, l];
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h;
  if (max === r) h = (g - b) / d + (g < b ? 6 : 0);
  else if (max === g) h = (b - r) / d + 2;
  else h = (r - g) / d + 4;
  return [h * 60, s, l];
}
function hslToRgb([h, s, l]) {
  const k = (n) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [f(0) * 255, f(8) * 255, f(4) * 255];
}
const rgba = (rgb, a = 1) => (a >= 1 ? rgbToHex(rgb) : `rgba(${rgb.map((v) => Math.round(v)).join(", ")}, ${+a.toFixed(3)})`);
const INK = [15, 23, 42]; // slate-900: the light look's ink, for faint lines and overlays

/** A colour class's colour: { family, shade } for a palette colour, { rgb } for any other; and its alpha. */
function parseColour(value, alphaPart) {
  let alpha = 1;
  if (alphaPart) {
    const raw = alphaPart.replace(/^\//, "").replace(/^\[|\]$/g, "");
    alpha = raw.includes(".") ? Number(raw) : Number(raw) / 100;
    if (raw.endsWith("%")) alpha = Number(raw.slice(0, -1)) / 100;
  }
  if (value === "white") return { rgb: [255, 255, 255], alpha, named: "white" };
  if (value === "black") return { rgb: [0, 0, 0], alpha, named: "black" };
  const hex = value.match(/^\[#([0-9a-fA-F]{3,8})\]$/);
  if (hex) return { rgb: hexToRgb(hex[1]), alpha };
  const pal = value.match(/^([a-z]+)-(\d{2,3})$/);
  if (pal && PALETTE[pal[1]] && PALETTE[pal[1]][pal[2]]) {
    return { family: pal[1], shade: Number(pal[2]), rgb: hexToRgb(PALETTE[pal[1]][pal[2]]), alpha };
  }
  return null;
}
const isNeutral = (c) => (c.family ? NEUTRAL.has(c.family) : rgbToHsl(c.rgb)[1] < 0.28 || luminance(c.rgb) < 0.02);
const shadeOf = (c, shade) => hexToRgb(PALETTE[c.family][shade]);

/** A surface (background, gradient stop). */
function lightSurface(c) {
  const L = luminance(c.rgb);
  if (c.named === "black" || (L < 0.002 && c.alpha < 0.9 && c.alpha >= 0.3)) {
    // A dimming layer behind a dialog or drawer.
    return rgba(INK, Math.min(c.alpha, 0.4));
  }
  if (c.named === "white" || (L > 0.7 && isNeutral(c))) {
    // A faint light wash on dark (hover, a raised row) becomes a faint dark wash; plain white stays white.
    return c.alpha >= 0.9 ? "#ffffff" : rgba(INK, Math.max(0.025, Math.min(c.alpha * 1.1, 0.08)));
  }
  if (c.family && !NEUTRAL.has(c.family)) {
    if (c.shade >= 800) return rgba(shadeOf(c, 50), 1);
    if (c.shade <= 400 && c.alpha < 0.5) return rgba(shadeOf(c, Math.max(c.shade, 400)), Math.min(c.alpha * 1.25, 0.2));
    return null; // a solid coloured button or badge reads the same on white
  }
  if (L >= 0.12) return null; // already light enough
  const [h, s] = rgbToHsl(c.rgb);
  let rgb;
  if (isNeutral(c)) {
    // Dark greys and navies: the darkest (wells, page level) a very light grey, panels white, raised ones a light grey.
    if (L < 0.004) rgb = hslToRgb([h, Math.min(s, 0.3), 0.975]);
    else if (L < 0.0125) rgb = [255, 255, 255];
    else if (L < 0.03) rgb = hslToRgb([h, Math.min(s, 0.3), 0.96]);
    else rgb = hslToRgb([h, Math.min(s, 0.3), 0.92]);
  } else {
    // A dark coloured panel (a dark red, a dark amber): a light tint of the same hue.
    rgb = hslToRgb([h, Math.min(s, 0.75), 0.96]);
  }
  return rgba(rgb, c.alpha < 0.98 && c.alpha >= 0.5 ? c.alpha : 1);
}

/** Text (and icons drawn in the text colour). */
function lightText(c) {
  const L = luminance(c.rgb);
  const a = Math.max(c.alpha, 0.78);
  if (c.named === "black") return null;
  // Dark greys from Tailwind's scale (text-slate-600 … 900) were written for light backgrounds: as they are.
  if (c.family && NEUTRAL.has(c.family) && c.shade >= 600) return null;
  if (isNeutral(c) || c.named === "white") {
    if (L > 0.8) return rgba(INK, c.alpha >= 0.9 ? 1 : Math.max(c.alpha, 0.8));
    if (L > 0.55) return rgba([30, 41, 59], a); // slate-800
    if (L > 0.28) return rgba([51, 65, 85], a); // slate-700
    if (L > 0.1) return rgba([71, 85, 105], a); // slate-600
    return rgba([100, 116, 139], a); // dim text on dark: slate-500, still AA on white
  }
  if (c.family) {
    const amberish = ["amber", "yellow", "lime", "orange", "brand"].includes(c.family);
    const target = c.shade <= 500 ? (amberish ? 800 : 700) : Math.max(c.shade, amberish ? 800 : 700);
    return rgba(shadeOf(c, Math.min(target, 900)), a);
  }
  const [h, s, l] = rgbToHsl(c.rgb);
  if (l <= 0.4) return null;
  return rgba(hslToRgb([h, Math.min(s, 0.8), 0.3]), a);
}

/** Lines (borders, dividers, rings). */
function lightLine(c) {
  const L = luminance(c.rgb);
  if (c.named === "white" || (isNeutral(c) && L > 0.6)) return rgba(INK, Math.max(0.08, Math.min(c.alpha * 1.4, 0.22)));
  if (c.family && !NEUTRAL.has(c.family)) {
    if (c.shade >= 700) return rgba(shadeOf(c, 200), Math.max(c.alpha, 0.9));
    if (c.shade <= 300) return rgba(shadeOf(c, 400), Math.max(c.alpha, 0.5));
    return null;
  }
  if (L >= 0.2) return null;
  if (isNeutral(c)) return rgba(L < 0.02 ? [226, 232, 240] : [203, 213, 225], c.alpha < 0.98 ? Math.max(c.alpha, 0.7) : 1);
  const [h] = rgbToHsl(c.rgb);
  return rgba(hslToRgb([h, 0.5, 0.82]), 1);
}

// ---- classes -------------------------------------------------------------------------------------------------------
const UTIL = /^(bg|text|border(?:-[trblxy])?|divide|ring|ring-offset|outline|from|via|to|fill|stroke|placeholder|decoration|accent|caret|shadow)-(\[#[0-9a-fA-F]{3,8}\]|white|black|[a-z]+-\d{2,3})(\/(?:\[[0-9.]+%?\]|\d{1,3}))?$/;

function files(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...files(path));
    else if (/\.(tsx|ts|mjs)$/.test(entry.name) && !entry.name.endsWith(".d.ts")) found.push(path);
  }
  return found;
}

const tokens = new Set();
for (const file of files(src)) {
  const text = readFileSync(file, "utf8");
  for (const match of text.matchAll(/[A-Za-z0-9_:\-[\]#/.%]+/g)) {
    const token = match[0];
    if (!/(bg|text|border|divide|ring|outline|from|via|to|fill|stroke|placeholder|decoration|accent|caret|shadow)-/.test(token)) continue;
    tokens.add(token);
  }
}

const escape = (cls) => cls.replace(/[^a-zA-Z0-9_-]/g, (ch) => `\\${ch}`);

function declarations(util, colour) {
  const [, kind] = util;
  const c = colour;
  switch (kind) {
    case "bg": {
      const v = lightSurface(c);
      return v && `background-color: ${v}`;
    }
    case "from": {
      const v = lightSurface(c);
      return v && `--tw-gradient-from: ${v} var(--tw-gradient-from-position); --tw-gradient-to: transparent var(--tw-gradient-to-position); --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to)`;
    }
    case "via": {
      const v = lightSurface(c);
      return v && `--tw-gradient-to: transparent var(--tw-gradient-to-position); --tw-gradient-stops: var(--tw-gradient-from), ${v} var(--tw-gradient-via-position), var(--tw-gradient-to)`;
    }
    case "to": {
      const v = lightSurface(c);
      return v && `--tw-gradient-to: ${v} var(--tw-gradient-to-position)`;
    }
    case "text":
    case "placeholder":
    case "decoration":
    case "caret":
    case "accent": {
      const v = lightText(c);
      const prop = { text: "color", placeholder: "color", decoration: "text-decoration-color", caret: "caret-color", accent: "accent-color" }[kind];
      return v && `${prop}: ${v}`;
    }
    case "fill":
    case "stroke": {
      const v = luminance(c.rgb) < 0.1 && isNeutral(c) ? lightSurface(c) : lightText(c);
      return v && `${kind}: ${v}`;
    }
    case "ring-offset": {
      const v = luminance(c.rgb) < 0.1 ? "#ffffff" : null;
      return v && `--tw-ring-offset-color: ${v}`;
    }
    case "ring": {
      const v = lightLine(c);
      return v && `--tw-ring-color: ${v}`;
    }
    case "outline": {
      const v = lightLine(c);
      return v && `outline-color: ${v}`;
    }
    case "shadow": {
      return luminance(c.rgb) < 0.05 ? `--tw-shadow-color: rgba(15, 23, 42, 0.08); --tw-shadow: var(--tw-shadow-colored)` : null;
    }
    default: {
      const v = lightLine(c);
      if (!v) return null;
      const side = { "border-t": "border-top-color", "border-b": "border-bottom-color", "border-l": "border-left-color", "border-r": "border-right-color" }[kind];
      if (side) return `${side}: ${v}`;
      if (kind === "border-x") return `border-left-color: ${v}; border-right-color: ${v}`;
      if (kind === "border-y") return `border-top-color: ${v}; border-bottom-color: ${v}`;
      return `border-color: ${v}`;
    }
  }
}

const SOLID = Object.keys(PALETTE).filter((f) => !NEUTRAL.has(f)).flatMap((f) => [500, 600, 700, 800].map((n) => `.bg-${f}-${n}`));
const SOLID_EXCEPT = `:not(${[...SOLID, ".bg-destructive", ".bg-primary"].join(", ")})`;

const rules = [];
for (const token of [...tokens].sort()) {
  const parts = token.split(":");
  const utility = parts.pop();
  const util = utility.match(UTIL);
  if (!util) continue;
  const colour = parseColour(util[2], util[3]);
  if (!colour) continue;
  let pseudo = "";
  let before = "";
  let media = null;
  let ok = true;
  for (const variant of parts) {
    if (PSEUDO[variant]) pseudo += PSEUDO[variant];
    else if (variant === "group-hover") before = ".group:hover ";
    else if (variant === "placeholder") pseudo += "::placeholder";
    else if (SCREENS[variant]) media = SCREENS[variant];
    else ok = false;
  }
  if (!ok) continue;
  let decl = declarations(util, colour);
  if (!decl) continue;
  let selector = `${before}.${escape(token)}${pseudo}`;
  // White (or near-white) text on a solid coloured button or badge stays as it is.
  if (util[1] === "text" && luminance(colour.rgb) > 0.55) selector += SOLID_EXCEPT;
  if (util[1] === "placeholder") selector += "::placeholder";
  if (util[1] === "divide") selector += " > :not([hidden]) ~ :not([hidden])";
  rules.push({ media, css: `:root[data-theme="light"] ${selector} { ${decl}; }` });
}

const plain = rules.filter((r) => !r.media).map((r) => r.css);
const byScreen = Object.values(SCREENS).map((px) => {
  const inside = rules.filter((r) => r.media === px).map((r) => `  ${r.css}`);
  return inside.length ? `@media (min-width: ${px}px) {\n${inside.join("\n")}\n}` : "";
}).filter(Boolean);

const css = `/* Made by scripts/gen-light-theme.mjs from the colour classes in src/: do not edit by hand. The light look of the
   pages written for the dark one (${rules.length} classes). */
${plain.join("\n")}
${byScreen.join("\n")}
`;

if (process.argv.includes("--check")) {
  const current = readFileSync(out, "utf8");
  if (current !== css) {
    console.error("src/styles/light-theme.generated.css is out of date: run node scripts/gen-light-theme.mjs");
    process.exit(1);
  }
} else {
  writeFileSync(out, css);
  console.log(`wrote ${out} (${rules.length} rules)`);
}
