import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { GUIDE_TOPICS } from "@/lib/guide";

/**
 * Every page of the console (src/app/**\/page.tsx, as tests/platform-ux-route-ledger.test.mjs counts them), with a
 * value in place of each [param] so the page can be opened: a made-up id (the page shows its "not found" or empty
 * state, which must fit the window too) or, for Settings → Guide, the first topic.
 */

const appDir = join(__dirname, "..", "..", "src", "app");

/** Pages shown without signing in (no console frame). */
export const PUBLIC_ROUTES = ["/", "/login", "/login/reset", "/login/oidc/callback", "/join", "/hands-off/confirm"];

function pageRoutes(directory: string): string[] {
  const routes: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name.startsWith("._")) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) routes.push(...pageRoutes(path));
    else if (entry.name === "page.tsx") {
      const parts = relative(appDir, path).split(sep).slice(0, -1).filter((part) => !/^\(.+\)$/.test(part));
      routes.push(`/${parts.join("/")}`.replace(/\/$/, "") || "/");
    }
  }
  return routes.sort();
}

export function openable(route: string): string {
  return route.replace(/\[topic\]/, GUIDE_TOPICS[0].slug).replace(/\[[^\]]+\]/g, "e2e-sample");
}

/** Every page route, as registered (with its [params]). */
export const ALL_ROUTES = pageRoutes(appDir);

/** The signed-in pages, ready to open. */
export const CONSOLE_ROUTES = ALL_ROUTES.filter((route) => !PUBLIC_ROUTES.includes(route)).map(openable);
