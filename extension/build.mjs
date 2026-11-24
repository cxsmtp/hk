import { build, context } from "esbuild";

const watch = process.argv.includes("--watch");
const pilot = process.argv.includes("--pilot");
const buildHash = String(process.env.HAWK_EXTENSION_BUILD_HASH || "dev").trim() || "dev";

const shared = {
  bundle: true,
  format: "esm",
  target: "es2022",
  minify: pilot,
  sourcemap: !pilot,
  legalComments: pilot ? "none" : "inline",
  define: {
    __HAWK_EXTENSION_BUILD_HASH__: JSON.stringify(buildHash),
  },
  logLevel: "info",
};

const tasks = [
  {
    entryPoints: ["src/service-worker.ts"],
    outfile: "dist/service-worker.js",
  },
  {
    entryPoints: ["src/content-script.ts"],
    outfile: "dist/content-script.js",
    format: "iife",
  },
  {
    entryPoints: ["src/options.ts"],
    outfile: "dist/options.js",
  },
];

for (const task of tasks) {
  if (watch) {
    const ctx = await context({
      ...shared,
      ...task,
      write: true,
    });
    await ctx.watch();
  } else {
    await build({
      ...shared,
      ...task,
      write: true,
    });
  }
}
