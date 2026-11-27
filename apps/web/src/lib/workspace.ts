/**
 * Workspaces without a workspace box: the sign-in page asks only for an email and a password (an email belongs to
 * one account on the installation). Someone in several workspaces signs in to the one they used last in this browser
 * (kept here, not a secret: a workspace id) and changes it from the account menu (components/workspace-switch.tsx).
 */

export const LAST_WORKSPACE_KEY = "hawk-last-workspace";

export function rememberedWorkspace(): string | null {
  try {
    return window.localStorage.getItem(LAST_WORKSPACE_KEY);
  } catch {
    return null;
  }
}

export function rememberWorkspace(tenantId: string): void {
  try {
    window.localStorage.setItem(LAST_WORKSPACE_KEY, tenantId);
  } catch {
    // Storage unavailable: the API's own choice is used next time.
  }
}

/** The workspace to open after signing in: the one used last here when the person still belongs to it. */
export function workspaceToOpen(tenants: Array<{ id: string }> | undefined, selected: string | undefined, remembered: string | null): string | undefined {
  if (remembered && tenants?.some((t) => t.id === remembered)) return remembered;
  return selected || tenants?.[0]?.id;
}

/** The optional ?workspace= of the sign-in page's address (an invitation, single sign-on for one workspace). */
export function workspaceFromAddress(search: string): string {
  const value = new URLSearchParams(search).get("workspace") || "";
  return /^[a-z0-9][a-z0-9-]{0,99}$/i.test(value) ? value : "";
}
