"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

const DEV_ROUTE_WARMUP_SESSION_KEY = "hawk_dev_route_warmup_v1";
const DEV_ROUTE_WARMUP_ROUTES = [
  "/dashboard/command-center",
  "/dashboard",
  "/analytics",
  "/ai-footprint",
  "/interaction-security",
  "/shadow-ai",
  "/ai-iam",
  "/monitoring",
  "/integrations",
  "/simulations",
  "/discovery/overview",
  "/discovery/applications",
  "/discovery/findings",
  "/runtime-intelligence/overview",
  "/runtime-intelligence/context-graph",
  "/auditor",
];

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function warmRoute(href: string): Promise<void> {
  const url = href.includes("?") ? `${href}&__dev_warmup=1` : `${href}?__dev_warmup=1`;
  try {
    await fetch(url, {
      method: "GET",
      cache: "no-store",
      credentials: "same-origin",
      keepalive: true,
    });
  } catch {
    // Best-effort only: compile warmup should never block UX.
  }
}

export function useDevRouteWarmup(): void {
  const router = useRouter();

  useEffect(() => {
    if (process.env.NODE_ENV !== "development") return;
    if (typeof window === "undefined") return;

    const seen = window.sessionStorage.getItem(DEV_ROUTE_WARMUP_SESSION_KEY);
    if (seen === "1") return;
    window.sessionStorage.setItem(DEV_ROUTE_WARMUP_SESSION_KEY, "1");

    let cancelled = false;
    const run = async () => {
      for (const href of DEV_ROUTE_WARMUP_ROUTES) {
        if (cancelled) return;
        try {
          // In production this is the native path, and in dev it's a harmless hint.
          router.prefetch(href);
        } catch {
          // Ignore prefetch failures and continue with direct warmup fetch.
        }
        await warmRoute(href);
        await wait(150);
      }
    };

    const idleCallback = (window as Window & {
      requestIdleCallback?: (cb: IdleRequestCallback, opts?: IdleRequestOptions) => number;
      cancelIdleCallback?: (id: number) => void;
    }).requestIdleCallback;

    const cancelIdleCallback = (window as Window & {
      requestIdleCallback?: (cb: IdleRequestCallback, opts?: IdleRequestOptions) => number;
      cancelIdleCallback?: (id: number) => void;
    }).cancelIdleCallback;

    let idleId: number | null = null;
    let timeoutId: number | null = null;

    if (typeof idleCallback === "function") {
      idleId = idleCallback(() => {
        void run();
      }, { timeout: 3000 });
    } else {
      timeoutId = window.setTimeout(() => {
        void run();
      }, 900);
    }

    return () => {
      cancelled = true;
      if (idleId !== null && typeof cancelIdleCallback === "function") {
        cancelIdleCallback(idleId);
      }
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
    };
  }, [router]);
}
