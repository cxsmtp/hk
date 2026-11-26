/**
 * Records and System pages: the audit log (FTR Command Center's public/js/audit.js), Connector API activity (FTR's
 * public/js/activity.js, the CxOne API audit), Get help (FTR's public/js/help.js and settings.js `help()`, with
 * CxMissionZero's conversation and statuses, public/app/help.js) and Network & proxy (CxMissionZero's
 * public/app/system.js). What each page shows, as those pages word it. The API is app/api/routers/records.py,
 * support.py and network.py.
 */

// ---- Audit log ------------------------------------------------------------------------------------------------------

export type AuditActor = { name: string; email: string } | null;
export type AuditEvent = {
  id: string;
  seq: number | null;
  at: string;
  actor: AuditActor;
  action: string;
  target: string;
  details: Record<string, unknown>;
  ip: string;
  mac: string | null;
};
export type AuditPage = { events: AuditEvent[]; more: boolean; people: { name: string; email: string }[]; actions: string[] };
export type AuditProblem = { seq: number | null; at: string | null; problem: string };
export type AuditVerify = {
  ok: boolean;
  entries: number;
  events: number;
  first: string | null;
  last: string | null;
  problems: AuditProblem[];
  unchained: number;
  brokenAt: number | null;
  why: string;
};

/** FTR's AUDIT_GROUPS, with the groups Hawk AI's actions use. */
export const AUDIT_GROUPS: Record<string, string> = {
  auth: "Sign-in",
  access: "Access",
  user: "People",
  people: "People",
  team: "Teams",
  role: "Roles",
  settings: "Settings",
  https: "HTTPS",
  sso: "Single sign-on",
  updates: "Updates",
  backup: "Backups",
  backups: "Backups",
  audit: "Audit log",
  system: "System",
  export: "Exports",
  terms: "Terms",
  me: "Own settings",
  setup: "Setup",
  licence: "Activation",
  activation: "Activation",
  support: "Get help",
  monitoring: "Connectors",
  connector: "Connectors",
  evidence_signing: "Evidence signing",
};

/** FTR's AUDIT_NAMES, for Hawk AI's actions. */
export const AUDIT_NAMES: Record<string, string> = {
  "auth.sign_in": "Signed in",
  "auth.sign_in.refused": "Sign-in refused",
  "auth.sign_out": "Signed out",
  "auth.password.changed": "Changed their password",
  "auth.password_reset.sent": "Password reset email sent",
  "auth.password_reset.done": "Reset their password by email",
  "auth.password_reset.refused": "Password reset refused",
  "auth.two_step.refused": "Two-step code refused",
  "auth.sso.signin": "Signed in with SSO",
  "auth.sso.refused": "SSO sign-in refused",
  "access.setup.refused": "First-administrator setup refused",
  "settings.network": "Changed the proxy",
  "settings.trust": "Changed the trusted certificates",
  "settings.support": "Changed Get help",
  "audit.verify": "Checked the audit log",
  "audit.export": "Exported the audit log",
  "support.case": "Raised a support case",
  "support.enhancement": "Requested an enhancement",
  "support.status": "Changed a request's status",
  "terms.accept": "Accepted the terms",
  "terms.accepted": "Accepted the licence agreement or terms of use",
  "terms.copy.resend": "Sent the licence agreement again",
};

export const auditBase = (action: string) => String(action).replace(/^refused: /, "");

export function auditLabel(action: string): string {
  const base = auditBase(action);
  const name =
    AUDIT_NAMES[base] ??
    (base.startsWith("audit.refusals_not_listed.")
      ? "Refusals not listed one by one"
      : base
          .split(".")
          .map((w, i) => (i === 0 ? AUDIT_GROUPS[w] ?? w : w.replace(/[-_]/g, " ")))
          .join(" · "));
  return String(action).startsWith("refused: ") ? `Refused: ${name}` : name;
}

export const auditRefused = (e: Pick<AuditEvent, "action">) => String(e.action).startsWith("refused: ") || /refused/.test(e.action);

/** FTR's auditDetails, as [key, value] pairs (the page renders each as a .kvp). */
export function auditDetails(details: Record<string, unknown> | null | undefined): [string, string][] {
  return Object.entries(details ?? {})
    .filter(([, v]) => v !== "" && v !== null && v !== undefined)
    .map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)]);
}

export function auditGroups(actions: string[]): string[] {
  return [...new Set(actions.map((a) => a.split(".")[0]))].sort((a, b) => (AUDIT_GROUPS[a] ?? a).localeCompare(AUDIT_GROUPS[b] ?? b));
}

/** FTR's verdict: "Intact: …" or "The log was changed at entry …", and every broken entry (CxMissionZero). */
export function verifyVerdict(v: AuditVerify, dateTime: (iso: string) => string): { ok: boolean; title: string; text: string } {
  if (v.ok) {
    return {
      ok: true,
      title: "",
      text: `Intact: all ${v.events.toLocaleString("en")} entries are chained, none changed or removed.${v.unchained ? ` ${v.unchained.toLocaleString("en")} older entries were written before the chain began and cannot be checked.` : ""}`,
    };
  }
  return { ok: false, title: "The log was changed", text: ` at entry ${(v.brokenAt ?? 0).toLocaleString("en")}${v.problems[0]?.at ? ` (${dateTime(v.problems[0].at)})` : ""}: ${v.why}.` };
}

export const FILTER_KEYS = ["q", "who", "what", "from", "to", "outcome"] as const;

export function queryString(filters: Record<string, string | string[] | undefined>): string {
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    const value = Array.isArray(v) ? v.join(",") : v;
    if (value) out.set(k, value);
  }
  return out.toString();
}

// ---- Evidence signing (app/api/routers/evidence_signing.py) ---------------------------------------------------------

export type EvidenceKey = { kid: string; fingerprint: string; alg: string; backend: string; key_name: string; created_at: string | null; retired_at: string | null };
export type EvidenceSigning = {
  backend: string;
  backend_label: string;
  key_ref: string;
  active: EvidenceKey | null;
  retired: EvidenceKey[];
  error: string;
  well_known_path: string;
  can_rotate: boolean;
};

/** The fingerprint as people compare it: groups of four, the first 32 hex digits (the rest in the key list). */
export function shortFingerprint(kid: string | null | undefined): string {
  return (String(kid || "").slice(0, 32).match(/.{1,4}/g) ?? []).join(" ");
}

export const ALGORITHM_LABELS: Record<string, string> = { EdDSA: "Ed25519", ES256: "ECDSA P-256 (ES256)" };

/** The X-Hawk-Evidence-Signature header of an export, as the .sig.json file saved beside it ('' when none). */
export function signatureFile(header: string | null | undefined): string {
  const value = String(header || "").trim();
  if (!value) return "";
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const text = new TextDecoder().decode(Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)));
    return `${JSON.stringify(JSON.parse(text), null, 2)}\n`;
  } catch {
    return "";
  }
}

// ---- Connector API activity ---------------------------------------------------------------------------------------

export type ConnectorCall = {
  at: string;
  connector: string;
  connectorId: string | null;
  method: string;
  host: string;
  path: string;
  status: number | null;
  ok: boolean;
  ms: number | null;
  detail: string;
};
export type ConnectorActivity = {
  events: ConnectorCall[];
  more: boolean;
  summary: { calls: number; avgMs: number; failed: number; connectors: number; hosts: number };
  connectors: string[];
  hosts: string[];
  keepDays: number;
};

export const CALL_OUTCOMES: [string, string][] = [
  ["ok", "Succeeded"],
  ["failed", "Any that did not succeed"],
];

// ---- Get help -----------------------------------------------------------------------------------------------------

export type SupportKind = "case" | "enhancement";
export type SupportStatus = "new" | "in-progress" | "waiting" | "completed" | "declined";
export type SupportRequest = {
  id: string;
  kind: SupportKind;
  subject: string;
  status: SupportStatus;
  priority: string;
  requester: { name: string; email: string };
  mine: boolean;
  createdAt: string;
  updatedAt: string;
  messages: number;
  page?: string;
  version?: string;
  conversation?: { at: string; name: string; team: boolean; mine: boolean; text: string }[];
  history?: { at: string; name: string; status: SupportStatus }[];
};
export type SupportChannel = { mode: "portal" | "email"; email: string; chosen?: "portal" | "email" };
export type SupportList = { team: boolean; statuses: Record<SupportStatus, string>; channel: SupportChannel; requests: SupportRequest[] };
export type Emailed = { sent: number; error: string };

/** FTR's HELP_KIND. */
export const HELP_KIND: Record<SupportKind, string> = { case: "Support case", enhancement: "Enhancement" };
/** CxMissionZero's HELP_STATUS, with FTR's chip tones. */
export const HELP_STATUS: Record<SupportStatus, [string, string]> = {
  new: ["New", ""],
  "in-progress": ["In progress", ""],
  waiting: ["Waiting for reply", "warn"],
  completed: ["Completed", "ok"],
  declined: ["Declined", "bad"],
};
export const HELP_PRIORITY: Record<string, string> = { low: "Low", normal: "Normal", high: "High", urgent: "Urgent" };

export function sentToast(r: { request: { id: string }; emailed?: Emailed }): { text: string; bad: boolean } {
  return r.emailed?.error
    ? { text: `${r.request.id} is kept, but the email did not go: ${r.emailed.error}`, bad: true }
    : { text: `${r.request.id} sent. You get an email with every answer.`, bad: false };
}

export function helpCrumbs(channel: SupportChannel | null | undefined): string {
  if (channel?.mode === "email") return `emailed to ${channel.email || "the support address"} · answered by email`;
  return "answered here · every answer and status change by email";
}

// ---- Network & proxy ----------------------------------------------------------------------------------------------

export type NetworkProxy = { url: string; username: string; noProxy: string; source: "settings" | "environment"; running: boolean; hasPassword: boolean };
export type NetworkRow = { direction: "In" | "Out"; what: string; host: string; port: string; route: string; why: string };
export type NetworkInfo = {
  proxy: NetworkProxy | null;
  changedAt: string;
  restart: string;
  targets: { host: string; port: number }[];
  requirements: NetworkRow[];
  text: string;
  restartRequired?: boolean;
};
export type NetworkStep = { step: "proxy" | "tunnel" | "certificate" | "answer"; ok: boolean; detail: string; status?: number; code?: string; issuer?: string };
export type NetworkResult = { ok: boolean; host: string; port: number; steps: NetworkStep[] };
export type NetworkCheck = { ok: boolean; via: string; results: NetworkResult[] };
export type CertificateFacts = {
  subject: string;
  organization: string;
  issuer: string;
  fingerprint256: string;
  validFrom: string;
  validTo: string;
  ca: boolean;
  selfSigned: boolean;
  vendor: string;
};
export type TrustedCertificate = CertificateFacts & { source: string; host: string; addedBy: string; addedAt: string; expired: boolean };
export type TrustDiagnosis = {
  status: "trusted" | "repaired" | "repairable" | "needs-consent" | "needs-upload" | "other";
  host: string;
  port: number;
  error?: string;
  candidate?: CertificateFacts;
  issuer?: string;
  vendor?: string;
  added?: CertificateFacts[];
};

/** CxMissionZero's step names; "Checkmarx One" is the service checked here. */
export const STEP_NAMES: Record<string, string> = { proxy: "Proxy", tunnel: "Connection", certificate: "Certificate", answer: "Service" };

/** CxMissionZero's networkAdvice: what to do when a step failed. */
export function networkAdvice(step: NetworkStep): string {
  if (step.ok) return "";
  if (step.step === "proxy") return "Check the proxy address and port with your network team.";
  if (step.step === "tunnel" && step.status === 407) return "The proxy wants a sign-in: give a user name and password, or ask for this server to be allowed by its IP address.";
  if (step.step === "tunnel" && step.status === 403) return "The proxy does not allow this host: ask your network team to allow it on port 443 for this server.";
  if (step.step === "tunnel") return "Ask your network team to allow this host on port 443 for this server, or set a proxy if one is required.";
  if (step.step === "certificate") return "Usually a proxy that inspects HTTPS: look at the certificate below and click Trust and connect, or ask for an exception from inspection.";
  return "";
}

/** CxMissionZero's line on what the server uses now. */
export function proxyNow(info: Pick<NetworkInfo, "proxy" | "changedAt" | "restart">): string {
  const p = info.proxy;
  let line = p
    ? `${p.source === "environment" ? "Using the proxy from the container (HTTPS_PROXY)" : "Using the proxy"} ${p.url}${p.username ? `, signing in as ${p.username}` : ""}.${p.running ? "" : ` Restart Hawk AI to use it: ${info.restart}.`}`
    : "Connecting directly, without a proxy.";
  if (!p && info.changedAt) line += ` Restart Hawk AI to use the change: ${info.restart}.`;
  return line;
}

export const TRUST_SOURCES: Record<string, string> = { detected: "Trusted from a connection", uploaded: "Uploaded", intermediate: "Fetched to complete a chain" };

/** Every certificate a Windows computer trusts, in one file on its desktop (CxMissionZero's WINDOWS_EXPORT). */
export const WINDOWS_EXPORT =
  "powershell -NoProfile -Command \"Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\LocalMachine\\CA, Cert:\\CurrentUser\\Root | ForEach-Object { '-----BEGIN CERTIFICATE-----'; [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks'); '-----END CERTIFICATE-----' } | Set-Content -Encoding ascii $env:USERPROFILE\\Desktop\\company-certificates.pem\"";

/** A certificate file as the server reads it: PEM text as it is, anything else (DER) in base64. */
export async function certificateFileData(file: File): Promise<string> {
  if (file.size > 3_000_000) throw new Error("That file is too large for certificates (3 MB at most).");
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = new TextDecoder("latin1").decode(bytes);
  if (text.includes("-----BEGIN")) return text;
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
