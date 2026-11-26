/**
 * Settings → HTTPS (apps/api/app/api/routers/https.py): what the API says, and the words the page shows. The page's
 * layout and wording are FTR Command Center's Settings → HTTPS (public/js/settings.js `https()`); the behaviour behind
 * it is CxMissionZero's (/settings/guide/https).
 */

export type HttpsMode = "http" | "both" | "https";

export type HttpsCheck = { id: string; level: "ok" | "warn" | "error"; title: string; detail?: string };

export type HttpsCertificateReport = {
  source?: string;
  kind?: string;
  usable?: boolean;
  trust?: string;
  error?: string;
  notes?: string[];
  summary?: {
    subject: string;
    names: string[];
    issuer: string;
    validFrom: string;
    validTo: string;
    daysLeft: number;
    selfSigned: boolean;
    keyType: string;
    fingerprint: string;
    chain: { subject: string; issuer: string; validTo: string }[];
  };
  checks?: HttpsCheck[];
};

export type AcmeStatus = {
  enabled: boolean;
  names: string[];
  email: string;
  staging: boolean;
  running: boolean;
  last: { at: string; ok?: boolean; error?: string; names?: string[]; running?: boolean } | null;
  issued: { at: string; validTo: string; names: string[]; issuer: string; staging: boolean } | null;
  daysLeft: number | null;
  renewsFrom: string | null;
  suggested: string[];
  fromEnvironment: string;
};

export type HttpsStatus = {
  mode: HttpsMode;
  startMode: HttpsMode;
  chosenHere: boolean;
  minVersion: "TLSv1.2" | "TLSv1.3";
  hsts: { enabled: boolean; maxAge: number; includeSubDomains: boolean };
  hstsActive: boolean;
  hstsAges: number[];
  selfSignedNames: string[];
  environmentCertificate: boolean;
  uploaded: { kind: string; at: string; by: string; subject: string; validTo: string } | null;
  previous: { subject: string; validTo: string; at: string } | null;
  request: { names: string[]; at: string; by: string; available: boolean } | null;
  certificate: HttpsCertificateReport | null;
  expiring: boolean;
  viewing: { secure: boolean; host: string; httpsUrl: string; httpUrl: string; httpRedirectPort: number; httpsPort: number };
  acme: AcmeStatus;
};

export type UploadFile = { name: string; data: string };

export const MODE_LABELS: Record<HttpsMode, string> = { http: "HTTP only", both: "HTTP and HTTPS", https: "HTTPS only" };
export const MODES: HttpsMode[] = ["http", "both", "https"];

/** How long browsers remember HSTS, as the page names it. */
export function hstsAgeLabel(seconds: number): string {
  return ({ 86400: "a day", 604800: "a week", 15768000: "half a year", 31536000: "a year" } as Record<number, string>)[seconds] ?? `${seconds} s`;
}

/** The chip next to "How the server is reached". */
export function modeChip(mode: HttpsMode): "ok" | "warn" | "bad" {
  return mode === "https" ? "ok" : mode === "both" ? "warn" : "bad";
}

/** The warnings and errors of a check, one line each ("Title: detail"). */
export function certificateIssues(report: HttpsCertificateReport | null | undefined): string[] {
  return (report?.checks ?? []).filter((c) => c.level === "error" || c.level === "warn").map((c) => `${c.title}${c.detail ? `: ${c.detail}` : ""}`);
}

export function isSelfSigned(report: HttpsCertificateReport | null | undefined): boolean {
  return Boolean(report?.summary?.selfSigned || /self/i.test(String(report?.source ?? "")));
}

/** The chip next to "Certificate in use", or null when there is none to show. */
export function certificateChip(status: Pick<HttpsStatus, "mode" | "certificate">): { kind: "ok" | "warn" | "bad"; text: string } | null {
  const report = status.certificate;
  if (status.mode === "http" || !report?.summary?.subject) return null;
  if (isSelfSigned(report)) return { kind: "warn", text: "Self-signed: browsers warn" };
  if (report.usable === false) return { kind: "bad", text: "Not usable" };
  return { kind: "ok", text: "Trusted" };
}

const SOURCES: Record<string, string> = { uploaded: "uploaded here", environment: "from the server options", "self-signed": "self-signed" };

export function sourceLabel(status: Pick<HttpsStatus, "certificate" | "uploaded" | "environmentCertificate">): string {
  const source = status.certificate?.source;
  if (source) return SOURCES[source] ?? source;
  return status.uploaded ? "uploaded here" : status.environmentCertificate ? "from the server options" : "self-signed";
}

/** Names typed into a field: separated by commas or spaces. */
export function splitNames(text: string): string[] {
  return String(text ?? "").split(/[\s,]+/).filter(Boolean);
}

/** The names the request (CSR) form starts with: those the self-signed certificate was made for, and this page's. */
export function requestNames(status: Pick<HttpsStatus, "selfSignedNames" | "viewing">): string {
  return [...new Set([...(status.selfSignedNames ?? []), status.viewing.host.replace(/:\d+$/, "")])].join(", ");
}

/** What the Let's Encrypt form says under its buttons. */
export function acmeLine(acme: AcmeStatus, when: (iso: string) => string): string {
  if (acme.running) return "Working on it…";
  if (acme.last?.error) return `Last attempt failed: ${acme.last.error}`;
  if (acme.last?.at) return `Last attempt ${when(acme.last.at)}`;
  return "";
}

/** A refusal that asks to confirm (the API's 409 with needsConfirm), as FTR's page asks it. */
export function asksToConfirm(message: string): boolean {
  return /Confirm|confirm/.test(message);
}
