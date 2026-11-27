/**
 * The product licence in the console (/settings/guide/licence): each installation works for 3 days from its first
 * start, then needs a `.hawkai` licence file made for its installation ID (apps/api/app/services/activation_service.py).
 * Used by the deactivation page (components/licence-gate.tsx), the admins' banner (components/licence-banner.tsx)
 * and Settings → Licence (app/settings/activation/page.tsx).
 */

/** Sent on the window when the API answers that Hawk AI has been deactivated (503 with deactivated: true). */
export const LICENCE_DEACTIVATED_EVENT = "hawk-licence-deactivated";

/** Sent on the window, with the product licence as its detail, when an imported licence moves its end. */
export const LICENCE_CHANGED_EVENT = "hawk-licence-changed";

export const DEACTIVATED_MESSAGE ="The product has been deactivated. Please reach out to Bhawani Singh.";

/** The licence file: its extension and the largest one the API takes. */
export const LICENCE_FILE_EXTENSION = ".hawkai";
export const MAX_LICENCE_FILE_BYTES = 16 * 1024;

/** GET /licence: open to everyone, also on the deactivation page. */
export type LicenceStatus = { active: boolean; until: string; trial?: boolean; installationId?: string; message: string };

export type LicenceActivation = { org: string; expires: string; at?: string | null; id?: string; scopes?: string[] };

/** The product licence's end, as /auth/me gives it to owners and admins. */
export type AdminLicence = {
  until: string;
  daysLeft: number;
  hoursLeft?: number;
  warn: boolean;
  trial?: boolean;
  installationId?: string;
  activation: LicenceActivation | null;
};

export type ProductLicence = AdminLicence & { active: boolean; message: string; trialEnds?: string };

export type InstalledLicence = {
  id: string;
  org: string;
  installationId: string;
  scopes: string[];
  maxTenants: number | null;
  maxUsers: number | null;
  issued: string;
  expires: string;
  at?: string | null;
  by?: string | null;
  daysLeft: number;
  valid: boolean;
  warn: boolean;
};

export type TenantsActivation = {
  org: string;
  maxTenants: number;
  maxUsers: number | null;
  expires: string;
  at?: string | null;
  by?: string | null;
  daysLeft: number;
  valid: boolean;
  warn: boolean;
};

export type LicenceHistoryEntry = {
  outcome: "imported" | "refused" | "identity" | string;
  id?: string;
  org?: string;
  installationId?: string;
  scopes?: string[];
  expires?: string;
  reason?: string;
  at: string;
  by: string;
};

/** GET /licence/status: Settings → Licence, and the deactivation page once an administrator has signed in. */
export type LicenceView = {
  canManage: boolean;
  keyConfigured: boolean;
  installationId: string;
  trial: { start: string; end: string; active: boolean };
  licence: InstalledLicence | null;
  tenants: TenantsActivation | null;
  product: ProductLicence;
  history: LicenceHistoryEntry[];
  maxFileBytes?: number;
};

export type LicenceImported = LicenceView & { imported: string };

/** Whether an API answer says Hawk AI has been deactivated (the licence gate's 503). */
export function isDeactivatedAnswer(status: number, body: unknown): boolean {
  return status === 503 && Boolean(body && typeof body === "object" && (body as { deactivated?: unknown }).deactivated === true);
}

/** The message in an API error's text: its "error" (the licence routes) or "detail", or the text itself. */
export function errorMessageFrom(text: string, fallback = "This licence could not be imported."): string {
  const raw = String(text || "").trim();
  if (!raw) return fallback;
  try {
    const body = JSON.parse(raw) as { error?: unknown; detail?: unknown };
    if (typeof body.error === "string" && body.error) return body.error;
    if (typeof body.detail === "string" && body.detail) return body.detail;
    return fallback;
  } catch {
    return raw;
  }
}

/** Why a chosen file cannot be a licence, before it is sent ('' when it may be one). The API checks it again. */
export function licenceFileProblem(file: { name: string; size: number } | null | undefined): string {
  if (!file) return "Choose a .hawkai licence file.";
  if (!String(file.name || "").toLowerCase().endsWith(LICENCE_FILE_EXTENSION)) return "Choose a .hawkai licence file: this file does not end in .hawkai.";
  if (file.size > MAX_LICENCE_FILE_BYTES) return "This file is too large to be a Hawk AI licence (at most 16 KB).";
  if (file.size === 0) return "This file is empty.";
  return "";
}

/** The last day a licence works, in UTC: the day before its end moment (which is the start of the next day). */
export function lastDayOf(until: string, month: "long" | "short" = "long"): string {
  const end = Date.parse(until);
  if (!Number.isFinite(end)) return "";
  return new Date(end - 1).toLocaleDateString("en-GB", { day: "numeric", month, year: "numeric", timeZone: "UTC" });
}

/** A day as Settings → Licence shows it. */
export function shortDate(iso: string | null | undefined): string {
  const at = Date.parse(String(iso || ""));
  if (!Number.isFinite(at)) return "";
  return new Date(at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

/** A moment to the minute, in UTC: "28 Nov 2026, 12:00 UTC". */
export function shortMoment(iso: string | null | undefined): string {
  const at = Date.parse(String(iso || ""));
  if (!Number.isFinite(at)) return "";
  const day = shortDate(iso);
  const time = new Date(at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" });
  return `${day}, ${time} UTC`;
}

const plural = (count: number, word: string) => (count === 1 ? `1 ${word}` : `${count} ${word}s`);

/** The time left, in days and hours below 3 days: "2 days 5 hours", "5 hours", "1 day". */
export function timeLeftText(hoursLeft: number | null | undefined, daysLeft: number): string {
  const hours = Number(hoursLeft);
  if (!Number.isFinite(hours) || hours <= 0) return plural(Math.max(0, daysLeft), "day");
  if (hours >= 72) return plural(Math.ceil(hours / 24), "day");
  const days = Math.floor(hours / 24);
  const rest = hours - days * 24;
  if (!days) return plural(rest, "hour");
  return rest ? `${plural(days, "day")} ${plural(rest, "hour")}` : plural(days, "day");
}

/**
 * The admins' banner: throughout the 3-day trial, and in a licence's last 30 days, with the end and the time left;
 * '' when there is none.
 */
export function licenceBannerText(licence: Pick<AdminLicence, "until" | "daysLeft" | "warn" | "hoursLeft" | "trial"> | null | undefined): string {
  if (!licence?.warn) return "";
  const left = timeLeftText(licence.hoursLeft, licence.daysLeft);
  if (licence.trial) {
    return `Hawk AI trial: ${left} left (until ${shortMoment(licence.until)}). Download the licence request under Settings → Licence, send it to Bhawani Singh, then upload the .hawkai licence you receive.`;
  }
  return `Hawk AI's licence ends at the end of ${lastDayOf(licence.until)} (UTC): ${left} left. Please reach out to Bhawani Singh for a new .hawkai licence, then upload it under Settings → Licence.`;
}

/** The product's line on Settings → Licence: "Hawk AI · Trial · Until 28 Nov 2026, 12:00 UTC" or with the licence. */
export function productStatusLine(product: Pick<ProductLicence, "active" | "until" | "activation" | "trial">): string {
  const state = !product.active ? "Deactivated" : product.trial ? "Trial" : "Licensed";
  const until = product.trial || !product.activation ? `Until ${shortMoment(product.until)}` : `Until the end of ${lastDayOf(product.until, "short")} (UTC)`;
  const parts = ["Hawk AI", state, until];
  if (product.activation?.org) parts.push(product.activation.org);
  return parts.join(" · ");
}

/** The licence's tenants scope: who it is for, how many tenants and users, until when. */
export function tenantsStatusLine(tenants: TenantsActivation): string {
  const parts = [
    "Several tenants",
    tenants.valid ? "Unlocked" : "Expired",
    tenants.org,
    `Up to ${plural(tenants.maxTenants, "tenant")}`,
    tenants.maxUsers ? `Up to ${plural(tenants.maxUsers, "active user")} in each` : "No cap on users",
    `Until ${shortDate(tenants.expires)}`,
  ];
  return parts.join(" · ");
}

/** What a history row says: the licence imported or refused, for whom, until when, who and when. */
export function historyLine(entry: LicenceHistoryEntry): string {
  const by = entry.by ? ` by ${entry.by}` : "";
  if (entry.outcome === "refused") return `Refused ${shortDate(entry.at)}${by}: ${entry.reason || "not a valid licence"}`;
  if (entry.outcome === "identity") return `${shortDate(entry.at)}: ${entry.reason || "a new installation ID"}`;
  const tenants = entry.scopes?.includes("tenants") ? " (several tenants)" : "";
  return `Licence for ${entry.org || "?"}${tenants}, until ${shortDate(entry.expires)} · imported ${shortDate(entry.at)}${by}`;
}

/** What the deactivation page says once a licence is imported. */
export function activatedText(until: string): string {
  return `Licensed until ${String(until).slice(0, 10)}. Opening Hawk AI…`;
}
