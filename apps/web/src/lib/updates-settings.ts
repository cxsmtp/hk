/**
 * Settings → Updates: what the page shows, laid out and worded as FTR Command Center's Updates page
 * (public/js/settings.js `updates()`), with what happens behind it from CxMissionZero (/settings/guide/updates,
 * /settings/guide/updates): the versions published as image tags, newest 3 then "Load 10 more", auto-update off by default
 * with an install hour, the latest and stable channels, and software integrity's five states.
 * The API is app/api/routers/updates.py.
 */

export type IntegrityState = "genuine" | "tampered" | "not-genuine" | "unconfirmed" | "unsigned" | "checking";

export type IntegrityOrigin = { ok: boolean; repository?: string; ref?: string; commit?: string; run?: string; signedAt?: string; logIndex?: number; reason?: string; reachable?: boolean };

export type Integrity = {
  state: IntegrityState;
  summary: string;
  at?: string;
  version?: string;
  commit?: string;
  image?: string;
  digest?: string;
  files?: { ok: boolean; checked: number; changed: string[]; missing: string[]; extra: string[]; counts: { changed: number; missing: number; extra: number } };
  origin?: IntegrityOrigin;
  repository?: string;
};

export type PublishedVersion = { version: string; label: string; digest: string; created: string; revision: string; tags: string[] };

export type UpdateEvent = { at: string; type: string; action?: string; from?: string; to?: string; by?: string; automatic?: boolean; error?: string; backup?: string };

export type UpdaterState = {
  connected: boolean;
  manages: boolean;
  heartbeat: { at: string; project: string; image: string; engine: string; engineError: string; services: Record<string, string> } | null;
  status: { id: string; action: string; version: string; tag: string; by: string; state: string; step: string; startedAt: string; finishedAt?: string; error?: string; from?: string; to?: string } | null;
  pending: { id: string; action: string; version: string; tag: string; by: string; at: string } | null;
  busy: boolean;
};

export type UpdateSettings = { auto: boolean; windowHour: number | null; channel: "latest" | "stable"; lastAutoAt: string | null; lastAutoResult: string };

export type UpdatesStatus = {
  image: string;
  images: Record<string, string>;
  running: { version: string; label: string };
  updater: UpdaterState;
  events: UpdateEvent[];
  lastCheck: { at: string; error: string; warning: string; versions: PublishedVersion[] } | null;
  updateAvailable: boolean;
  latest: PublishedVersion | null;
  settings: UpdateSettings;
  failed: string[];
  offline: boolean;
  serverTime: { zone: string; hour: number; minute: number };
  integrity: Integrity;
};

/** "0.2.0" → "HK-00.02.00" (the console's corner, apps/api/app/version.py). */
export function label(version: string): string {
  const parts = String(version || "")
    .split(".")
    .slice(0, 3)
    .map((p) => Number.parseInt(p, 10) || 0);
  while (parts.length < 3) parts.push(0);
  return `HK-${parts.map((n) => String(n).padStart(2, "0")).join(".")}`;
}

/** -1, 0 or 1, comparing "1.0.27"-style versions (FTR's cmpVer). */
export function cmpVer(a: string, b: string): number {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i += 1) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0) ? -1 : 1;
  return 0;
}

/** Software integrity's chip: FTR's INTEG, with CxMissionZero's five states (/settings/guide/updates). */
export const INTEG: Record<IntegrityState, [string, string]> = {
  genuine: ["ok", "Genuine"],
  tampered: ["bad", "Files changed"],
  "not-genuine": ["bad", "Not signed by the release workflow"],
  unconfirmed: ["warn", "Not confirmed yet"],
  unsigned: ["", "Development copy"],
  checking: ["", "Checking…"],
};

/** Recent events (FTR's `ev`, for the updater's events). */
export const EVENTS: Record<string, string> = {
  switch: "Switched",
  "rolled-back": "Rolled back",
  restart: "Restarted",
  failed: "Not installed",
  refused: "Refused",
  unchanged: "Already running",
};

export const eventBad = (type: string): boolean => /fail|refused|rolled/.test(type);

/** One line of an event, as FTR joins it. */
export function eventLine(e: UpdateEvent): string {
  return [e.to && e.action !== "restart" ? label(e.to) : "", e.from ? `from ${label(e.from)}` : "", e.error, e.automatic ? "by auto-update" : e.by ? `by ${e.by}` : ""].filter(Boolean).join(" · ");
}

/** The versions to show: the newest `shown` (3, then 10 more at a time) and the running one, which is always shown. */
export function visibleVersions(versions: PublishedVersion[], running: string, shown: number): { rows: PublishedVersion[]; more: number } {
  const rows = versions.filter((v, i) => i < shown || v.version === running);
  return { rows, more: Math.max(0, versions.length - rows.length) };
}

export type VersionRow = {
  chips: [string, string][];
  action: "update" | "rollback" | null;
  why: string;
};

/** A version's chips and its one action: Update now (newer), Roll back to this (older), nothing for the running one. */
export function versionRow(v: PublishedVersion, u: Pick<UpdatesStatus, "running" | "failed" | "updater">): VersionRow {
  const running = v.version === u.running.version;
  const failed = u.failed.includes(v.version);
  const chips: [string, string][] = [];
  if (running) chips.push(["ok", "Running"]);
  if (v.tags.includes("latest")) chips.push(["", "Latest"]);
  if (v.tags.includes("stable")) chips.push(["ok", "Stable"]);
  if (failed) chips.push(["bad", "Failed to start"]);
  if (running) return { chips, action: null, why: "" };
  if (!u.updater.connected || !u.updater.manages) return { chips, action: null, why: "not available" };
  return { chips, action: cmpVer(v.version, u.running.version) > 0 ? "update" : "rollback", why: "" };
}

/** The hours auto-update may install in: any time, or one hour of the day in the server's time zone. */
export const HOURS: { value: string; text: string }[] = [{ value: "", text: "any time" }, ...Array.from({ length: 24 }, (_, h) => ({ value: String(h), text: `${String(h).padStart(2, "0")}:00` }))];

export const serverNow = (t: UpdatesStatus["serverTime"]): string => `${String(t.hour).padStart(2, "0")}:${String(t.minute).padStart(2, "0")}${t.zone ? ` (${t.zone})` : ""}`;

/** What the updater is doing, or why updates from this page cannot run (FTR's "not started by the launcher" callout). */
export function updaterCallout(updater: UpdaterState): string {
  if (!updater.connected)
    return "The updater is not running, so versions are listed here but cannot be installed from this page. It runs with the published images: set HAWK_RELEASE in deploy/.env (latest, stable or a version) and run sudo deploy/install.sh again.";
  if (!updater.manages) return `The updater cannot update this installation: ${updater.heartbeat?.engineError || "it does not look after Hawk AI's services yet."}`;
  return "";
}

/** The overlay while the updater works (FTR's waitForRestart). */
export const SWITCHING_TEXT =
  "A backup is taken first. Hawk AI stops for the few seconds the new version takes to start, and this page reloads on it by itself. If it does not come up within 150 s, the version before is put back by itself, with its data.";

/** The newest version on the channel the page follows, and whether it is newer than what runs (FTR's `avail`). */
export function available(u: Pick<UpdatesStatus, "latest" | "running" | "failed">): PublishedVersion | null {
  const v = u.latest;
  return v && cmpVer(v.version, u.running.version) > 0 && !u.failed.includes(v.version) ? v : null;
}

/** The files that differ, as FTR lists them under Software integrity. */
export function changedFiles(i: Integrity): string {
  if (!i.files || i.files.ok) return "";
  return [...i.files.changed.map((f) => `changed ${f}`), ...i.files.missing.map((f) => `missing ${f}`), ...i.files.extra.map((f) => `added ${f}`)].slice(0, 8).join(" · ");
}

/** The notice owners and admins see at the top of every page (CxMissionZero: an alert when they sign in). */
export function integrityNoticeText(notice: { state: IntegrityState; summary: string } | null): string {
  if (!notice) return "";
  return `Software integrity: ${INTEG[notice.state]?.[1] ?? notice.state}. ${notice.summary}`;
}
