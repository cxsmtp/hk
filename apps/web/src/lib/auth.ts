export type Session = {
  accessToken: string;
  refreshToken: string;
  tenantId: string;
  userRole?: string;
  user: {
    id: string;
    email: string;
    full_name: string;
  };
};

const KEY = "ai-control-plane-session";
const SESSION_EVENT = "hawk-session-changed";

function emitSessionChange() {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new Event(SESSION_EVENT));
}

export function setSession(session: Session) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(KEY, JSON.stringify(session));
  emitSessionChange();
}

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function clearSession() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(KEY);
  emitSessionChange();
}

export function updateSessionTokens(accessToken: string, refreshToken: string) {
  if (typeof window === "undefined") return;
  const current = getSession();
  if (!current) return;
  setSession({
    ...current,
    accessToken,
    refreshToken,
  });
}

export const SESSION_CHANGE_EVENT = SESSION_EVENT;
