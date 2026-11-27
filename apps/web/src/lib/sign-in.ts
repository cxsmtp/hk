/**
 * Sign-in in the console (/settings/guide/people-and-access), ported from CxMissionZero's public/app/session.js: two-step sign-in after
 * the password, "Forgot your password?" and its emailed link, and the sentences single sign-on comes back with.
 */

/** The password was right and a code comes next (apps/api/app/api/routers/auth.py TwoStepChallenge). */
export type TwoStepChallenge = {
  two_step: true;
  ticket: string;
  minutes: number;
  setup?: TwoStepSetup | null;
};

/** What an authenticator app is given: the key, the key in groups of four, and the address its QR code carries. */
export type TwoStepSetup = { secret: string; key: string; otpauth: string };

/** Two-step sign-in for the person signed in (/auth/me two_step). */
export type TwoStepState = { available: boolean; on: boolean; since: string; recoveryLeft: number; required: boolean };

export function isTwoStepChallenge(value: unknown): value is TwoStepChallenge {
  return typeof value === "object" && value !== null && (value as { two_step?: unknown }).two_step === true && typeof (value as { ticket?: unknown }).ticket === "string";
}

/** The API's answer to a refused step, from the text of the error the API client throws: its sentence, and whether
 * the password has to be typed again (the ticket is over). */
export function refusalFrom(text: string, fallback = "That did not work. Try again."): { message: string; restart: boolean; sso: boolean } {
  const raw = String(text || "").trim();
  try {
    const body = JSON.parse(raw) as { detail?: unknown; error?: unknown; restart?: unknown; sso?: unknown };
    const message = typeof body.detail === "string" && body.detail ? body.detail : typeof body.error === "string" && body.error ? body.error : fallback;
    return { message, restart: body.restart === true, sso: body.sso === true };
  } catch {
    return { message: raw && !raw.startsWith("<") ? raw : fallback, restart: false, sso: false };
  }
}

/** The emailed link: /login/reset#reset=<token>, 43 URL-safe characters (256 bits). "" when the address has none. */
export function resetLinkToken(hash: string): string {
  return /^#reset=([A-Za-z0-9_-]{43})$/.exec(String(hash || ""))?.[1] ?? "";
}

/** The server sends people back with a short code (#sso=…), never with the provider's own words: these are the sentences. */
export const SSO_REFUSALS: Record<string, string> = {
  off: "Single sign-on is not turned on here. Sign in with your email and password.",
  setup: "Single sign-on is not set up completely. Ask an administrator.",
  provider: "The identity provider could not be reached, or did not answer as expected. Try again in a moment, or ask an administrator.",
  cancelled: "The identity provider did not sign you in. Try again.",
  expired: "That sign-in took too long, or was started in another browser. Try again.",
  token: "The identity provider's answer could not be verified, so nobody was signed in. Ask an administrator.",
  email: "The identity provider did not give a verified email address for you. Ask an administrator.",
  domain: "Your email address is not one that may sign in here this way.",
  unknown: "The identity provider signed you in, but you have no access here yet. Ask an administrator to add you.",
  link: "Your account here is linked to another account at the identity provider. Ask an administrator.",
  disabled: "This account is disabled. Ask an administrator.",
  busy: "Too many sign-in attempts from this address. Wait a few minutes.",
  // Hawk's own rule: the identity provider must vouch for a second factor (amr).
  mfa: "The identity provider did not confirm a second factor for this sign-in. Ask an administrator.",
};

/** The sentence for a #sso=<code> address, or "" when the address has none. */
export function ssoRefusal(hash: string): string {
  const code = /^#sso=([a-z]{1,20})$/.exec(String(hash || ""))?.[1] ?? "";
  if (!code) return "";
  return SSO_REFUSALS[code] ?? SSO_REFUSALS.token;
}

/** What the two-step page says above the code field. */
export function twoStepHint({ setup, recovery }: { setup: boolean; recovery: boolean }): string {
  if (setup) return "Then enter the six-digit code the app shows, to turn two-step sign-in on.";
  if (recovery) return "Enter one of the recovery codes you saved when you turned two-step sign-in on. Each works once.";
  return "Enter the six-digit code your authenticator app shows for Hawk AI.";
}

/** Who may reset a forgotten password by email, as Settings → Sign-in names the choices. */
export const RESET_POLICY_OPTIONS: Array<[string, string]> = [
  ["everyone", "Everyone with a password"],
  ["not-admins", "Everyone except those who manage people"],
  ["off", "Nobody: a person who manages people sets a temporary password"],
];

/** The administrator's sign-in rules (/auth/sign-in-settings). */
export type SignInSettings = {
  passwordReset: "everyone" | "not-admins" | "off";
  passwordResetReady: { ready: boolean; policy: string; missing: string[] };
  twoStepRequired: boolean;
  sso: {
    enabled: boolean;
    provision: "existing" | "create";
    role: string;
    domains: string[];
    requireVerifiedEmail: boolean;
    passwordAdminsOnly: boolean;
    callbackUrl: string;
    roles: string[];
    providers: Array<{ key: string; kind: string; label: string; workspace: string; issuer: string; clientId: string }>;
  };
  email: { configured: boolean; host: string; port: number; from: string; tested: boolean };
  serverAddress: string;
  /** The idle sign-out in force; sessionIdleSet: the value set on Settings → Sign-in (null: SESSION_IDLE_MINUTES). */
  sessionIdleMinutes: number;
  sessionIdleSet?: number | null;
  sessionIdleDefault?: number;
  /** The password rule (apps/api/app/services/password_policy.py; /settings/guide/compliance). */
  passwordRule?: PasswordRule & { text: string };
  /** The notice shown on the sign-in page. */
  banner?: string;
  /** What "Apply the recommended baseline" sets. */
  baseline?: PasswordRule & { sessionIdleMinutes: number };
};

export type PasswordRule = { minLength: number; classes: number; history: number; maxAgeDays: number };

export type SignInPerson = {
  id: string;
  email: string;
  name: string;
  role: string;
  active: boolean;
  twoStep: boolean;
  ssoLinked: boolean;
  locked: boolean;
  lastSignIn: string;
  you: boolean;
};

/** Hours, as FTR's "Idle sign-out: After N hours" says it. */
export function idleHours(minutes: number): string {
  const hours = Number(minutes || 0) / 60;
  return Number.isInteger(hours) ? String(hours) : hours.toFixed(1);
}

/** The text of the email domains field, as a list the API takes ("a.com, b.com"). */
export function domainList(text: string): string[] {
  return String(text || "")
    .split(/[\s,;]+/)
    .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean);
}
