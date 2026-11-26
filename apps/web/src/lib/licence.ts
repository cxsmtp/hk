/**
 * The product licence and activation codes in the console (/settings/guide/licence), ported from CxMissionZero's
 * public/deactivated.js, public/app/core.js (renderLicenceBanner) and public/app/system.js (renderActivation).
 */

/** Sent on the window when the API answers that Hawk AI has been deactivated (503 with deactivated: true). */
export const LICENCE_DEACTIVATED_EVENT = "hawk-licence-deactivated";

/** Sent on the window, with the product licence as its detail, when a code applied under Settings moves its end. */
export const LICENCE_CHANGED_EVENT = "hawk-licence-changed";

export const DEACTIVATED_MESSAGE ="The product has been deactivated. Please reach out to Bhawani Singh.";

export type LicenceStatus = { active: boolean; until: string; message: string };

export type LicenceActivation = { org: string; expires: string; at?: string | null };

/** The product licence's end, as /auth/me gives it to owners and admins. */
export type AdminLicence = {
  until: string;
  daysLeft: number;
  warn: boolean;
  activation: LicenceActivation | null;
};

export type ProductLicence = AdminLicence & { active: boolean; message: string };

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

export type ActivationHistoryEntry = {
  id: string;
  org: string;
  scope: string;
  action: string;
  expires: string;
  at: string;
  by: string;
};

export type ActivationView = {
  canManage: boolean;
  keyConfigured: boolean;
  tenants: TenantsActivation | null;
  product: ProductLicence;
  history: ActivationHistoryEntry[];
};

export type ActivationApplied = ActivationView & { applied: string };

/** Whether an API answer says Hawk AI has been deactivated (the licence gate's 503). */
export function isDeactivatedAnswer(status: number, body: unknown): boolean {
  return status === 503 && Boolean(body && typeof body === "object" && (body as { deactivated?: unknown }).deactivated === true);
}

/** The message in an API error's text: its "error" (the licence routes) or "detail", or the text itself. */
export function errorMessageFrom(text: string, fallback = "This activation code is not valid."): string {
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

/** The last day a licence works, in UTC: the day before its end moment (which is the start of the next day). */
export function lastDayOf(until: string, month: "long" | "short" = "long"): string {
  const end = Date.parse(until);
  if (!Number.isFinite(end)) return "";
  return new Date(end - 1).toLocaleDateString("en-GB", { day: "numeric", month, year: "numeric", timeZone: "UTC" });
}

/** A day as the Activation codes page shows it. */
export function shortDate(iso: string | null | undefined): string {
  const at = Date.parse(String(iso || ""));
  if (!Number.isFinite(at)) return "";
  return new Date(at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

const plural = (count: number, word: string) => (count === 1 ? `1 ${word}` : `${count} ${word}s`);

/**
 * The admins' banner in the licence's last 30 days, with the date and the days left; '' when there is none. From
 * 2 January 2027 for the built-in end.
 */
export function licenceBannerText(licence: Pick<AdminLicence, "until" | "daysLeft" | "warn"> | null | undefined): string {
  if (!licence?.warn) return "";
  return `Hawk AI stops working at the end of ${lastDayOf(licence.until)} (UTC) unless it is activated: ${plural(licence.daysLeft, "day")} left. Please reach out to Bhawani Singh for an activation code, then enter it under Settings → Activation codes.`;
}

/** The product's line on the Activation codes page: "Hawk AI · Active · Until the end of 31 Jan 2027 (UTC)". */
export function productStatusLine(product: Pick<ProductLicence, "active" | "until" | "activation">): string {
  const parts = ["Hawk AI", product.active ? "Active" : "Deactivated", `Until the end of ${lastDayOf(product.until, "short")} (UTC)`];
  if (product.activation?.org) parts.push(product.activation.org);
  return parts.join(" · ");
}

/** The tenants code's line: who it is for, how many tenants and users, until when. */
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

/** What a history row says: the code, for whom, until when, who entered it and when. */
export function historyLine(entry: ActivationHistoryEntry): string {
  const what = entry.scope === "product" ? "Product code" : entry.scope === "tenants" ? "Tenants code" : entry.scope;
  return `${what} for ${entry.org}, until ${shortDate(entry.expires)} · entered ${shortDate(entry.at)}${entry.by ? ` by ${entry.by}` : ""}`;
}

/** What the deactivation page says once a code is accepted. */
export function activatedText(until: string): string {
  return `Activated until ${String(until).slice(0, 10)}. Opening Hawk AI…`;
}
