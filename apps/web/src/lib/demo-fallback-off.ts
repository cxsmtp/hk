// What "@/lib/demo-fallback" resolves to in every build but the demo build (next.config.mjs, demo-build.mjs): no demo
// data at all, so an API error stays an error and an empty result stays empty.
import type { Session } from "@/lib/auth";

export function isDemoFallbackEnabled(): boolean {
  return false;
}

export function demoFallbackRequest(_path: string, _init?: RequestInit, _session?: Session | null): unknown | null {
  return null;
}

export function resetDemoFallbackState(): void {}

export function demoDataShown(): boolean {
  return false;
}

export function subscribeDemoData(_listener: () => void): () => void {
  return () => {};
}
