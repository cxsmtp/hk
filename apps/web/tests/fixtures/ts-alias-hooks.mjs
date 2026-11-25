// Lets a node:test file import the console's TypeScript modules as a production build sees them: "@/x" resolves to
// src/x (.ts, .tsx, .mjs, .js), extensionless relative imports get their extension, and "@/lib/demo-fallback" resolves
// to src/lib/demo-fallback-off.ts, as next.config.mjs does for every build but the demo build. Node strips the types.
import { existsSync } from "node:fs";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const SRC = new URL("../../src/", import.meta.url);
const EXTENSIONS = [".ts", ".tsx", ".mjs", ".js", "/index.ts"];

function withExtension(url) {
  const path = fileURLToPath(url);
  if (existsSync(path) && !path.endsWith("/")) return url;
  for (const extension of EXTENSIONS) {
    if (existsSync(path + extension)) return pathToFileURL(path + extension);
  }
  return null;
}

export function registerProductionAliases() {
  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "@/lib/demo-fallback") {
        return { url: new URL("lib/demo-fallback-off.ts", SRC).href, shortCircuit: true };
      }
      if (specifier.startsWith("@/")) {
        const found = withExtension(new URL(specifier.slice(2), SRC));
        if (found) return { url: found.href, shortCircuit: true };
      }
      if ((specifier.startsWith("./") || specifier.startsWith("../")) && context.parentURL?.startsWith("file:")) {
        const found = withExtension(new URL(specifier, context.parentURL));
        if (found) return { url: found.href, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
  });
}
