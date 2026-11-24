export function parseDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

export function formatDateTime(value?: string | null): string {
  const date = parseDate(value);
  return date ? date.toLocaleString() : "-";
}

export function decisionValue(value: unknown): string {
  const text = String(value || "").trim().toLowerCase();
  return text || "unknown";
}

export function decisionLabel(value: unknown): string {
  const text = decisionValue(value);
  return text
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function decisionBadgeClass(value: unknown): string {
  const decision = decisionValue(value);
  if (decision === "allow" || decision === "approved") return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  if (decision === "block" || decision === "deny" || decision === "denied") return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  if (["warn", "redact", "require_justification", "hold_for_approval", "require_approval"].includes(decision)) {
    return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  }
  return "border-slate-500/40 bg-slate-500/20 text-slate-200";
}

export function severityBadgeClass(value: unknown): string {
  const severity = String(value || "").trim().toLowerCase();
  if (severity === "critical") return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  if (severity === "high") return "border-orange-500/40 bg-orange-500/20 text-orange-200";
  if (severity === "med" || severity === "medium") return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  if (severity === "low") return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  return "border-slate-500/40 bg-slate-500/20 text-slate-200";
}

export function safePercent(value: number): string {
  const bounded = Math.max(0, Math.min(100, Math.round(value)));
  return `${bounded}%`;
}
