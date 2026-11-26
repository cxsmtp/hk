/**
 * Who is signed in, for the console's own use: never the tokens. Those are HttpOnly cookies set by the API
 * (apps/api/app/core/session_cookies.py), out of reach of any script on the page; what is kept here only says whom
 * to show and which tenant to ask for.
 */
export type Session = {
  tenantId: string;
  userRole?: string;
  user: {
    id: string;
    email: string;
    full_name: string;
  };
};

const KEY = "hawk-console-session";
// Where earlier versions kept the tokens themselves: removed on sight, so they do not linger in the browser.
const LEGACY_KEY = "ai-control-plane-session";
const SESSION_EVENT = "hawk-session-changed";

// The header that asks the API for the cookie session, and the CSRF cookie and header (double submit).
export const SESSION_MODE_HEADER = "X-Hawk-Session";
export const CSRF_HEADER = "X-CSRF-Token";
const CSRF_COOKIES = ["__Host-hawk_csrf", "hawk_csrf"];

function emitSessionChange() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(SESSION_EVENT));
}

function dropLegacy() {
  try {
    window.localStorage.removeItem(LEGACY_KEY);
  } catch {
    // Storage unavailable: nothing was kept there either.
  }
}

/** Only the non-secret fields are written, whatever the caller passes. */
export function setSession(session: Session) {
  if (typeof window === "undefined") return;
  dropLegacy();
  const kept: Session = { tenantId: session.tenantId, userRole: session.userRole, user: session.user };
  window.localStorage.setItem(KEY, JSON.stringify(kept));
  emitSessionChange();
}

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;
  dropLegacy();
  const raw = window.localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Session;
    return parsed && typeof parsed.tenantId === "string" && parsed.tenantId ? parsed : null;
  } catch {
    return null;
  }
}

export function clearSession() {
  if (typeof window === "undefined") return;
  dropLegacy();
  window.localStorage.removeItem(KEY);
  emitSessionChange();
}

/** The CSRF token the API set with the session (a readable cookie), echoed in X-CSRF-Token. */
export function csrfToken(): string {
  if (typeof document === "undefined") return "";
  const jar = String(document.cookie || "").split(";").map((part) => part.trim());
  for (const name of CSRF_COOKIES) {
    const found = jar.find((part) => part.startsWith(`${name}=`));
    if (found) {
      try {
        return decodeURIComponent(found.slice(name.length + 1));
      } catch {
        return found.slice(name.length + 1);
      }
    }
  }
  return "";
}

/** The headers every console request to the API carries: the cookie session, and the CSRF token when there is one. */
export function sessionHeaders(headers: Headers = new Headers()): Headers {
  headers.set(SESSION_MODE_HEADER, "cookie");
  const csrf = csrfToken();
  if (csrf) headers.set(CSRF_HEADER, csrf);
  return headers;
}

export const SESSION_CHANGE_EVENT = SESSION_EVENT;
