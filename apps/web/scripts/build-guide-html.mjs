#!/usr/bin/env node
// The administrator's guide (Settings → Guide, src/lib/guide) as one self-contained, printable HTML file, from the same
// data as the console pages. The file is not part of the repository: give where to write it.
//
//   node scripts/build-guide-html.mjs <output.html>
//
// Runs on Node 20.6+ (as the tests do): the guide's TypeScript is compiled on the fly by tests/fixtures/ts-alias-loader.mjs.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { register } from "node:module";
import { dirname, resolve } from "node:path";

const out = process.argv[2];
if (!out || out.startsWith("-")) {
  console.error("Usage: node scripts/build-guide-html.mjs <output.html>");
  process.exit(2);
}

register("../tests/fixtures/ts-alias-loader.mjs", import.meta.url);
const { guideHtml } = await import("../src/lib/guide/html.ts");

let version = "";
try {
  version = `HK-${readFileSync(new URL("../../../VERSION", import.meta.url), "utf8")
    .trim()
    .split(".")
    .map((part) => part.padStart(2, "0"))
    .join(".")}`;
} catch {
  version = "";
}

const target = resolve(out);
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, guideHtml({ version, generatedAt: new Date().toISOString().slice(0, 10) }), "utf8");
console.log(`Wrote ${target}`);
