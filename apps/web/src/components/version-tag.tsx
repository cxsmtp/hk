import { displayVersion } from "@/lib/access";

/**
 * This build's version, bottom-left on every screen including sign-in (CxMissionZero's corner version). Read from the
 * repository's VERSION file when the console is built (next.config.mjs); the API gives the same on /health.
 */
export function VersionTag() {
  const version = displayVersion(process.env.NEXT_PUBLIC_HAWK_VERSION || "");
  return (
    <div
      data-ui="hawk-version"
      aria-label={`Hawk AI version ${version}`}
      className="pointer-events-none fixed bottom-1.5 right-3 z-40 hidden select-text font-mono text-[11px] text-slate-600 md:block"
    >
      {version}
    </div>
  );
}
