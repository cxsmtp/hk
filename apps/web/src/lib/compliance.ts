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
  /** "Set by the server's administrators." for a workspace admin: the settings are the whole server's. */
  readOnlyNote?: string;
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

// ---- Framework packs (apps/api/app/services/compliance_packs; GET /compliance/packs) --------------------------------

/** A control of the registry, as one requirement of a pack shows it. */
export type PackControlStatus = "met" | "partly" | "not_configured" | "not_applicable";
export type RequirementStatus = "met" | "partly" | "gap" | "not_applicable" | "attested" | "yours";
export type Applicability = "product" | "customer" | "organisational";

export type PackControl = {
  id: string;
  title: string;
  status: PackControlStatus;
  reason: string;
  scope: "product" | "administrator" | "customer";
  href: string;
  label: string;
  planned: boolean;
};

export type PackRecord = {
  status: "in_place" | "not_applicable";
  note: string;
  reference: string;
  by: string;
  at: string | null;
  expiresAt: string | null;
  current: boolean;
};

export type PackRequirement = {
  id: string;
  title: string;
  applicability: Applicability;
  status: RequirementStatus;
  why: string;
  note: string;
  controls: PackControl[];
  evidence: string[];
  attestation: PackRecord | null;
};

export type PackFramework = { name: string; short: string; version: string; publisher: string; jurisdiction: string; url: string };

export type PackCounts = Record<RequirementStatus, number> & {
  total: number;
  byApplicability: Record<Applicability, Record<RequirementStatus | "total", number>>;
};

export type PackSummary = { id: string; version: string; optional: boolean; framework: PackFramework; summary: string; counts: PackCounts };

export type PacksOverview = { packs: PackSummary[]; disclaimer: string; evaluatedAt: string; mayRecord: boolean; mayExport: boolean };

export type PackView = {
  id: string;
  version: string;
  optional: boolean;
  framework: PackFramework;
  summary: PackCounts;
  scope: string;
  sources: Array<{ title: string; url: string }>;
  notes: Array<{ id: string; title: string; text: string }>;
  requirements: PackRequirement[];
  disclaimer: string;
  evaluatedAt: string;
  mayRecord: boolean;
  mayExport: boolean;
};

export const REQUIREMENT_LABELS: Record<RequirementStatus, string> = {
  met: "Met",
  partly: "Partly met",
  gap: "Gap",
  not_applicable: "Not applicable",
  attested: "Recorded in place",
  yours: "Your process",
};

export const REQUIREMENT_CHIP: Record<RequirementStatus, string> = { met: "ok", partly: "warn", gap: "bad", not_applicable: "", attested: "ok", yours: "" };

export const CONTROL_LABELS: Record<PackControlStatus, string> = { met: "Met", partly: "Partly", not_configured: "Not configured", not_applicable: "Not applicable" };

export const CONTROL_CHIP: Record<PackControlStatus, string> = { met: "ok", partly: "warn", not_configured: "bad", not_applicable: "" };

export const APPLICABILITY_LABELS: Record<Applicability, string> = {
  product: "Hawk AI (product)",
  customer: "You, with Hawk AI",
  organisational: "Your organisation",
};

/** The status filter of the pack view: everything, or met, partly, gaps, or what is the organisation's own. */
export type StatusFilter = "all" | "met" | "partly" | "gap" | "yours";

export const STATUS_FILTERS: Array<{ key: StatusFilter; label: string }> = [
  { key: "all", label: "All" },
  { key: "met", label: "Met" },
  { key: "partly", label: "Partly" },
  { key: "gap", label: "Gaps" },
  { key: "yours", label: "Yours to record" },
];

const FILTER_MATCH: Record<StatusFilter, RequirementStatus[]> = {
  all: ["met", "partly", "gap", "not_applicable", "attested", "yours"],
  met: ["met", "attested", "not_applicable"],
  partly: ["partly"],
  gap: ["gap"],
  yours: ["yours"],
};

const SHOW_ORDER: RequirementStatus[] = ["gap", "partly", "yours", "attested", "met", "not_applicable"];

/** The requirements a pack view shows for the chosen applicability ("all" or one) and status filter, gaps first. */
export function filterRequirements(items: PackRequirement[], applicability: Applicability | "all", status: StatusFilter): PackRequirement[] {
  return items
    .map((r, index) => ({ r, index }))
    .filter(({ r }) => (applicability === "all" || r.applicability === applicability) && FILTER_MATCH[status].includes(r.status))
    .sort((a, b) => SHOW_ORDER.indexOf(a.r.status) - SHOW_ORDER.indexOf(b.r.status) || a.index - b.index)
    .map(({ r }) => r);
}

/** The first control of a requirement that is not met and can be set: where to go to close the gap. */
export function fixFor(item: PackRequirement): PackControl | null {
  return item.controls.find((c) => (c.status === "not_configured" || c.status === "partly") && !c.planned) ?? null;
}

/** One line of counts for a pack. */
export function packLine(counts: PackCounts): string {
  const done = counts.met + counts.attested + counts.not_applicable;
  return `${done} of ${counts.total} met or recorded · ${counts.partly} partly · ${counts.gap} gaps · ${counts.yours} yours to record`;
}

/** The evidence bundle's window as a query (dates or times as given; the API defaults to the last 30 days). */
export function evidenceQuery(from: string, to: string): string {
  return incidentQuery(from, to);
}
