/**
 * Self-recovery and the diagnostics bundle on Settings → Backups & health (app/api/routers/diagnostics.py,
 * app/services/self_recovery.py): the issues Hawk AI found, what it did about each, what needs the OEM, and the bundle
 * to download and send. An installation admin sees everything; another tenant's admin sees their own tenant's issues
 * and the installation's as plain lines with a reference.
 */

export type RecoveryStatus = "open" | "recovering" | "recovered" | "needs_oem";

export type RecoveryIssue = {
  reference: string;
  signature: string;
  title: string;
  detail: string;
  status: RecoveryStatus;
  statusLabel: string;
  firstSeen?: string | null;
  lastSeen?: string | null;
  lastAction?: string | null;
  lastResult?: string | null;
  needsOemAt?: string | null;
  recoveredAt?: string | null;
  attempts: number;
  limit: number;
  action: string;
};

export type RecoveryEvent = {
  at: string;
  reference: string;
  signature: string;
  title: string;
  action?: string;
  result: string;
  detail: string;
};

export type RecoverySignature = { id: string; title: string; action: string; maxAttempts: number; windowHours: number };

export type DiagnosticsView = {
  scope: "installation" | "tenant";
  canRun: boolean;
  lastRunAt: string;
  everyMinutes: number;
  issues: RecoveryIssue[];
  history: RecoveryEvent[];
  needsOem: boolean;
  needsOemReferences: string[];
  prepared: { name: string; at: string; reference?: string; title?: string; bytes?: number } | null;
  signatures: RecoverySignature[];
};

export const RESULT_WORDS: Record<string, string> = {
  found: "Found",
  tried: "Tried",
  fixed: "Fixed",
  verified: "Checked: healthy",
  recovered: "Recovered",
  failed: "Did not help",
  "breaker-open": "Paused (circuit breaker)",
  needs_oem: "Needs OEM help",
  reset: "Tried again",
};

export const STATUS_TONE: Record<RecoveryStatus, "ok" | "warn" | "bad"> = { open: "warn", recovering: "warn", recovered: "ok", needs_oem: "bad" };

/** The chip at the top of the box: needs the OEM, working on something, or nothing to do. */
export function recoveryChip(view: DiagnosticsView | null): { tone: "ok" | "warn" | "bad"; label: string; text: string } {
  if (!view) return { tone: "warn", label: "Not known", text: "Self-recovery has not reported yet." };
  if (view.needsOem) {
    return {
      tone: "bad",
      label: "Needs OEM help",
      text: `Hawk AI could not fix ${view.needsOemReferences.length === 1 ? "one issue" : `${view.needsOemReferences.length} issues`} on its own and stopped trying. Download the diagnostics bundle and send it to the OEM with the reference${view.needsOemReferences.length === 1 ? "" : "s"} ${view.needsOemReferences.join(", ")}.`,
    };
  }
  const working = view.issues.filter((i) => i.status === "open" || i.status === "recovering").length;
  if (working) return { tone: "warn", label: "Recovering", text: `Hawk AI is putting ${working === 1 ? "one issue" : `${working} issues`} right on its own.` };
  return { tone: "ok", label: "Nothing to fix", text: "Hawk AI found nothing it needs to put right." };
}

/** One line of the history: when, the reference, what happened. */
export function historyLine(event: RecoveryEvent, when: (iso: string) => string): string {
  const word = RESULT_WORDS[event.result] ?? event.result;
  return `${when(event.at)} · ${event.reference} · ${event.title}: ${word}${event.detail ? `. ${event.detail}` : ""}`;
}

/** The bundle's name from the response, or one made here. */
export function bundleFileName(disposition: string | null, now: Date = new Date()): string {
  const named = /filename="([^"]+)"/.exec(disposition ?? "")?.[1];
  return named && /^hawk-ai-diagnostics-[\w.-]+\.tar\.gz$/.test(named) ? named : `hawk-ai-diagnostics-${now.toISOString().slice(0, 10)}.tar.gz`;
}
