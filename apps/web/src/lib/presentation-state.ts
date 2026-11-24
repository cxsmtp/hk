export type PresentationState = "loading" | "ready-populated" | "ready-empty" | "unavailable" | "stale";

export type PresentationStateInput = {
  loading: boolean;
  hasData: boolean;
  unavailable?: boolean;
  stale?: boolean;
};

export function resolvePresentationState({
  loading,
  hasData,
  unavailable = false,
  stale = false,
}: PresentationStateInput): PresentationState {
  if (hasData) return stale || unavailable || loading ? "stale" : "ready-populated";
  if (loading) return "loading";
  if (unavailable) return "unavailable";
  return "ready-empty";
}
