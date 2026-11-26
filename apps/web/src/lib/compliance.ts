/**
 * Settings → Compliance (/settings/guide/compliance; apps/api/app/api/routers/compliance.py): how this installation
 * stands against the controls of Dubai's Information Security Regulation (DESC ISR v3), the UAE IA Standard and
 * India's CERT-In directions, the clock, encryption at rest, how long activity is kept, and the incident report.
 */

export type ControlStatus = "met" | "partial" | "action" | "customer";

export type ComplianceControl = {
  id: string;
  title: string;
  refs: string[];
  status: ControlStatus;
  detail: string;
  /** product: Hawk AI does it; administrator: a setting here; customer: the server the customer runs. */
  owner: "product" | "administrator" | "customer";
  evidence: { href: string; label: string };
};

export type ComplianceSettings = {
  activityRetentionDays: number;
  connectorRetentionDays: number;
  minRetentionDays: number;
  maxRetentionDays: number;
  dataLocation: string;
  dataLocationDefault: string;
  deploymentRegion: string;
  incidentContact: string;
};

export type ClockStatus = {
  synchronized: boolean | null;
  kernel: { synchronized: boolean | null; source: string; maxErrorMs?: number | null; reason?: string };
  ntp: { server: string; ok: boolean; offsetSeconds?: number; stratum?: number; reason?: string } | null;
  ntpServer: string;
  databaseSkewSeconds: number | null;
  timeZone: string;
  utc: string;
  problems: string[];
};

export type ComplianceView = {
  standards: Array<{ key: string; name: string; by: string; applies: string; url: string }>;
  controls: ComplianceControl[];
  summary: Record<ControlStatus, number>;
  clock: ClockStatus;
  encryption: {
    backups: { encrypted: boolean | null; source: string; optedOut?: boolean };
    secrets: { encrypted: boolean; what: string };
    disk: { confirmed: boolean; what: string };
  };
  settings: ComplianceSettings;
  dataLocation: string;
  mayChange: boolean;
};

export const STATUS_LABELS: Record<ControlStatus, string> = {
  met: "Met",
  partial: "Partly met",
  action: "Needs a setting",
  customer: "Customer's server",
};

/** The chip class the Settings pages use for each status. */
export const STATUS_CHIP: Record<ControlStatus, string> = { met: "ok", partial: "warn", action: "bad", customer: "" };

export const OWNER_LABELS: Record<ComplianceControl["owner"], string> = {
  product: "Hawk AI",
  administrator: "A setting here",
  customer: "The customer's server",
};

/** The clock in words. */
export function clockSentence(clock: ClockStatus | null | undefined): string {
  if (!clock) return "";
  if (clock.synchronized === true) {
    const offset = clock.ntp?.ok && typeof clock.ntp.offsetSeconds === "number" ? ` (${Math.abs(clock.ntp.offsetSeconds)} s from ${clock.ntp.server})` : "";
    return `Synchronised${offset}.`;
  }
  if (clock.synchronized === false) return clock.problems.join(" ") || "Not synchronised.";
  return "Could not be read from here: check that the host runs chrony or systemd-timesyncd, or set TIME_SYNC_NTP_SERVER.";
}

/** The incident report's window as a query: from and to as given (dates or times), else the last 24 hours. */
export function incidentQuery(from: string, to: string): string {
  const params = new URLSearchParams();
  if (from.trim()) params.set("from", from.trim());
  if (to.trim()) params.set("to", to.trim());
  return params.toString();
}

/** The retention entered on the page: a whole number of days within the limits, else null. */
export function retentionDays(value: string, min: number, max: number): number | null {
  const text = String(value ?? "").trim();
  if (!/^\d{1,4}$/.test(text)) return null;
  const days = Number(text);
  return days >= min && days <= max ? days : null;
}
