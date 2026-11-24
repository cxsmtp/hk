import Link from "next/link";

import type { PresentationState } from "@/lib/presentation-state";

export type OperationalStateProps = {
  state: PresentationState;
  title?: string;
  description?: string;
  onRetry?: () => void;
  signInHref?: string;
  className?: string;
};

const DEFAULT_COPY: Record<Exclude<PresentationState, "ready-populated">, { title: string; description: string }> = {
  loading: { title: "Loading", description: "Fetching the latest information." },
  "ready-empty": { title: "Nothing to show yet", description: "No records are available for this view." },
  unavailable: { title: "Information unavailable", description: "This source could not be reached. Try again when it is available." },
  stale: { title: "Showing earlier information", description: "A newer refresh is still in progress or unavailable. Review the information below with its original timestamp." },
};

export function OperationalState({ state, title, description, onRetry, signInHref, className = "" }: OperationalStateProps) {
  if (state === "ready-populated") return null;

  const copy = DEFAULT_COPY[state];
  const compact = state === "stale";
  return (
    <div
      role="status"
      aria-live={state === "loading" ? "polite" : "off"}
      data-presentation-state={state}
      className={`${compact ? "px-4 py-3" : "px-5 py-8"} rounded-xl border ${state === "unavailable" || compact ? "border-amber-300/20 bg-amber-300/[0.05]" : "border-white/[0.09] bg-white/[0.025]"} ${className}`}
    >
      <p className={`text-sm font-medium ${state === "unavailable" || compact ? "text-amber-100" : "text-slate-200"}`}>{title ?? copy.title}</p>
      <p className="mt-1 text-xs leading-5 text-slate-400">{description ?? copy.description}</p>
      {(onRetry || signInHref) && state !== "loading" ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {onRetry ? <button type="button" onClick={onRetry} className="rounded-lg border border-orange-300/30 px-3 py-1.5 text-xs font-medium text-orange-200 hover:bg-orange-300/10">Try again</button> : null}
          {signInHref ? <Link href={signInHref} className="rounded-lg border border-white/15 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-white/5">Sign in</Link> : null}
        </div>
      ) : null}
    </div>
  );
}
