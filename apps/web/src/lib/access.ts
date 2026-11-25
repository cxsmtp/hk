/**
 * First sign-in in the console (deploy/README.md), ported from CxMissionZero's public/app/session.js: a temporary
 * password is changed before anything else, then the terms of use (TERMS.md) are accepted, by an owner or admin for
 * the organisation first and then by each person. The API answers 403 with one of two codes until then
 * (apps/api/app/core/access_gate.py), and the console turns them into those two pages.
 */

/** Sent on the window when the API answers that this person must choose a new password first. */
export const PASSWORD_CHANGE_EVENT = "hawk-password-change-required";

/** Sent on the window when the API answers that the terms of use must be accepted first. */
export const TERMS_REQUIRED_EVENT = "hawk-terms-required";

export const PASSWORD_CHANGE_REQUIRED = "password_change_required";
export const TERMS_REQUIRED = "terms_required";

export type AccessNeeded = "password" | "terms" | null;

/** Where this person stands with the terms of use (/auth/me). */
export type TermsState = {
  version: string;
  organisationAccepted: boolean;
  accepted: boolean;
  canAcceptForOrganisation: boolean;
};

/** The terms of use, as GET /terms gives them. */
export type TermsView = {
  version: string;
  text: string;
  notice: string;
  organisation: { at: string; by: string; via: string } | null;
  organisationName: string;
  you?: { accepted: boolean; at: string | null; canAcceptForOrganisation: boolean };
};

/** What an API answer asks for first: a new password, the terms of use, or nothing. */
export function accessNeededFrom(status: number, text: string): AccessNeeded {
  if (status !== 403) return null;
  try {
    const body = JSON.parse(String(text || "")) as { code?: unknown };
    if (body.code === PASSWORD_CHANGE_REQUIRED) return "password";
    if (body.code === TERMS_REQUIRED) return "terms";
  } catch {
    return null;
  }
  return null;
}

/** What the console shows first for a signed-in person, from /auth/me. */
export function accessNeededFor(me: { must_change_password?: boolean; terms?: TermsState | null } | null | undefined): AccessNeeded {
  if (!me) return null;
  if (me.must_change_password) return "password";
  if (me.terms && !me.terms.accepted) return "terms";
  return null;
}

export const MIN_PASSWORD_LENGTH = 12;

/** The password rule, as the API checks it (apps/api/app/services/passwords.py): "" when the password will do. */
export function passwordProblem(password: string): string {
  const text = String(password || "");
  if (text.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (new TextEncoder().encode(text).length > 72) return "That password is too long.";
  if (new Set(text).size < 5) return "That password is too repetitive.";
  return "";
}

/** What the change-password page says is wrong before asking the API, or "". */
export function newPasswordProblem(current: string, next: string, repeat: string): string {
  if (!current) return "Enter your current password.";
  if (next !== repeat) return "The two new passwords are not the same.";
  if (next === current) return "Choose a password different from the current one.";
  return passwordProblem(next);
}

/** What the terms page asks of this person. */
export function termsStep(state: Pick<TermsState, "organisationAccepted" | "canAcceptForOrganisation">): "organisation" | "wait" | "person" {
  if (state.organisationAccepted) return "person";
  return state.canAcceptForOrganisation ? "organisation" : "wait";
}

/** "1.2.3" → "HK-01.02.03": the version shown bottom-left on every screen (apps/api/app/version.py). */
export function displayVersion(semver: string): string {
  const parts = String(semver || "")
    .trim()
    .split(".")
    .slice(0, 3)
    .map((piece) => Number.parseInt(piece, 10) || 0);
  while (parts.length < 3) parts.push(0);
  return `HK-${parts.map((n) => String(n).padStart(2, "0")).join(".")}`;
}

/** A setup code as people type it: upper-case, spaces dropped (the API compares it the same way). */
export function cleanSetupCode(code: string): string {
  return String(code || "").replace(/\s+/g, "").toUpperCase();
}

const escapeHtml = (value: string) =>
  String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

/**
 * TERMS.md as HTML for the terms page: headings, paragraphs, nested lists, bold and code, everything else escaped
 * (CxMissionZero's termsHtml). The top heading is left out: the page has its own title.
 */
export function termsHtml(markdown: string): string {
  const inline = (text: string) =>
    escapeHtml(text)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>");
  const out: string[] = [];
  const lists: number[] = [];
  let paragraph: string[] = [];
  const flush = () => {
    if (paragraph.length) out.push(`<p>${inline(paragraph.join(" "))}</p>`);
    paragraph = [];
  };
  const closeLists = (depth = 0) => {
    while (lists.length > depth) {
      out.push("</li></ul>");
      lists.pop();
    }
  };
  for (const line of String(markdown || "").split("\n")) {
    const item = line.match(/^(\s*)- (.*)$/);
    if (item) {
      flush();
      const depth = Math.floor(item[1].length / 2) + 1;
      if (lists.length < depth) {
        out.push("<ul><li>");
        lists.push(depth);
      } else {
        closeLists(depth);
        out.push("</li><li>");
      }
      out.push(inline(item[2]));
      continue;
    }
    if (!line.trim()) {
      flush();
      closeLists();
      continue;
    }
    const heading = line.match(/^(#{1,3}) (.*)$/);
    if (heading) {
      flush();
      closeLists();
      if (heading[1].length > 1) out.push(`<h${heading[1].length + 1}>${inline(heading[2])}</h${heading[1].length + 1}>`);
      continue;
    }
    if (lists.length && /^\s+\S/.test(line)) out.push(` ${inline(line.trim())}`);
    else paragraph.push(line.trim());
  }
  flush();
  closeLists();
  return out.join("").replace(/<ul><li><\/li><li>/g, "<ul><li>");
}
