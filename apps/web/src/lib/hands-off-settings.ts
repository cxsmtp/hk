/**
 * Settings → Hands-off and the self-check: what the pages show, in CxMissionZero's words (public/index.html
 * #set-handsoff, public/app/automation.js renderHandsOff and renderHealth) and FTR Command Center's settings look. The
 * API is app/api/routers/hands_off.py.
 */

export type HandsOffSettings = {
  on: boolean;
  statusTo: string[];
  statusDay: number;
  statusHour: number;
  pausedUntil: string;
  replies: boolean;
  imapHost: string;
  imapPort: number;
  lastStatusAt: string;
};

export type SelfCheckProblem = {
  key: string;
  title: string;
  detail: string;
  tenant: string;
  outside: boolean;
  since: string;
  lastAt: string;
  checks: number;
  tried: string[];
  notifiedAt: string;
  caseId: string;
};

export type SelfCheckEvent = { at: string; kind: string; message: string; key?: string };

export type SelfCheckHealth = {
  lastCheckAt: string;
  everyMinutes: number;
  problems: SelfCheckProblem[];
  events: SelfCheckEvent[];
  maintainer: string;
};

export type HandsOffView = {
  handsOff: HandsOffSettings;
  canSave: boolean;
  ready: { smtp: boolean; serverUrl: boolean };
  paused: boolean;
  commands: Record<string, string>;
  health: SelfCheckHealth;
};

export type LinkAnswer = { ok: boolean; action?: string; title: string; message: string; confirm?: string };

/** The days as MZ offers them: Monday first, Sunday (0) last. */
export const DAYS: [number, string][] = [
  [1, "Monday"],
  [2, "Tuesday"],
  [3, "Wednesday"],
  [4, "Thursday"],
  [5, "Friday"],
  [6, "Saturday"],
  [0, "Sunday"],
];

export const HOURS: [number, string][] = Array.from({ length: 24 }, (_, i) => [i, `${String(i).padStart(2, "0")}:00`]);

/** The lines above the questions: is email tested, is the server address set (MZ's #ho-ready), and a pause. */
export function readiness(view: Pick<HandsOffView, "ready" | "paused" | "handsOff">): { ok: boolean; text: string }[] {
  const lines = [
    { ok: view.ready.smtp, text: view.ready.smtp ? "Email server tested" : "Set up and test the email server first (Settings → Sign-in)." },
    { ok: view.ready.serverUrl, text: view.ready.serverUrl ? "Server address set: the email buttons work" : "Set the server address (PUBLIC_URL) so the email buttons work." },
  ];
  return view.paused ? [...lines, { ok: false, text: `Paused until ${view.handsOff.pausedUntil.slice(0, 16).replace("T", " ")} UTC` }] : lines;
}

/** The self-check's chip, as FTR's Health panel shows the audit log's: one chip, then the words. */
export function healthChip(health: SelfCheckHealth | null | undefined): { tone: "ok" | "bad" | "warn"; label: string; text: string } {
  if (!health || !health.lastCheckAt) return { tone: "warn", label: "Not checked yet", text: `The self-check runs every ${health?.everyMinutes ?? 5} minutes.` };
  const open = health.problems ?? [];
  if (!open.length) return { tone: "ok", label: "All checks pass", text: `Last check: ${health.lastCheckAt.slice(0, 16).replace("T", " ")} UTC.` };
  return { tone: "bad", label: open.length === 1 ? "1 problem" : `${open.length} problems`, text: `Last check: ${health.lastCheckAt.slice(0, 16).replace("T", " ")} UTC.` };
}

/** One open problem in a line: what, why, since when, what was tried, and its case. */
export function problemLine(p: SelfCheckProblem): string {
  const tried = p.tried?.length ? ` Tried: ${p.tried.join("; ")}.` : "";
  const outside = p.outside ? " The problem is on the far side." : "";
  return `${p.title}: ${p.detail}${/[.!?]$/.test(p.detail) ? "" : "."}${outside}${tried}${p.caseId ? ` Support case ${p.caseId}.` : ""}`;
}

/** What the questions save (MZ's handsOffPayload, without the Checkmarx reminders). */
export function handsOffPayload(form: { status: boolean; statusTo: string; statusDay: number; statusHour: number; replies: boolean; imapHost: string; imapPort: string }, on = true) {
  return {
    handsOff: {
      on,
      statusTo: form.status ? form.statusTo : "",
      statusDay: form.statusDay,
      statusHour: form.statusHour,
      replies: form.replies,
      imapHost: form.imapHost.trim(),
      imapPort: Number(form.imapPort) || 993,
    },
  };
}

/** A link's token from the address: /hands-off/confirm#a=<token>. "" when the address has none. */
export function linkToken(hash: string): string {
  const found = /(?:^#|&)a=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/.exec(hash || "");
  return found ? found[1] : "";
}
