// Module hooks for tests/fixtures/ts-alias-hooks.mjs (registered with module.register, Node 20.6+): "@/x" resolves to
// src/x (.ts, .tsx, .mjs, .js), extensionless relative imports get their extension, "@/lib/demo-fallback" resolves to
// src/lib/demo-fallback-off.ts as next.config.mjs does for every build but the demo build, and TypeScript is compiled
// with the project's own typescript package, so the tests run on Node 20 (CI and the images) as well as on newer Node.
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const SRC = new URL("../../src/", import.meta.url);
const EXTENSIONS = [".ts", ".tsx", ".mjs", ".js", "/index.ts"];
const ts = createRequire(import.meta.url)("typescript");

function withExtension(url) {
  const path = fileURLToPath(url);
  if (existsSync(path) && !path.endsWith("/")) return url;
  for (const extension of EXTENSIONS) {
    if (existsSync(path + extension)) return pathToFileURL(path + extension);
  }
  return null;
}

export async function resolve(specifier, context, nextResolve) {
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
}

export async function load(url, context, nextLoad) {
  if (url.startsWith("file:") && /\.tsx?$/.test(url)) {
    const source = readFileSync(fileURLToPath(url), "utf8");
    const { outputText } = ts.transpileModule(source, {
      fileName: fileURLToPath(url),
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
        jsx: ts.JsxEmit.ReactJSX,
        verbatimModuleSyntax: false,
        isolatedModules: true,
      },
    });
    return { format: "module", source: outputText, shortCircuit: true };
  }
  return nextLoad(url, context);
}
