import { normalizeBrowserType, signInWithCredentials, STORAGE_KEYS, getSettings } from "./policy-sync";

function byId<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing element: ${id}`);
  return node as T;
}

function setStatus(message: string): void {
  byId<HTMLDivElement>("status").textContent = message;
}

function sessionLabel(active: boolean): string {
  return active ? "Session active (token hidden, not persisted locally)" : "";
}

function setManagedLockState(locked: boolean): void {
  for (const id of [
    "backendUrl",
    "tenantId",
    "accessToken",
    "refreshToken",
    "browser",
    "browserProfile",
    "pilotHostname",
    "pilotDeviceType",
    "pilotOsVersion",
  ]) {
    byId<HTMLInputElement | HTMLSelectElement>(id).disabled = locked;
  }
  byId<HTMLButtonElement>("saveButton").disabled = locked;
}

async function loadSettingsIntoForm(): Promise<void> {
  const settings = await getSettings();
  const state = await chrome.runtime.sendMessage({ type: "GET_EXTENSION_STATE" }) as {
    ok: boolean;
    lastSyncAt: string | null;
    lastHealthReportAt: string | null;
    lastHealthReportStatus: string | null;
    telemetryQueueDepth?: number;
    lastError?: string | null;
    hasRefreshToken?: boolean;
    policy: { policy_version?: string; platform_mode?: string } | null;
  };
  byId<HTMLInputElement>("backendUrl").value = settings.backendUrl;
  byId<HTMLInputElement>("tenantId").value = settings.tenantId;
  byId<HTMLInputElement>("accessToken").value = sessionLabel(Boolean(settings.accessToken));
  byId<HTMLInputElement>("refreshToken").value = sessionLabel(Boolean(settings.refreshToken));
  byId<HTMLSelectElement>("browser").value = settings.browser;
  byId<HTMLInputElement>("browserProfile").value = settings.browserProfile;
  byId<HTMLInputElement>("pilotHostname").value = settings.pilotHostname;
  byId<HTMLSelectElement>("pilotDeviceType").value = settings.pilotDeviceType;
  byId<HTMLInputElement>("pilotOsVersion").value = settings.pilotOsVersion;
  byId<HTMLInputElement>("loginEmail").value = settings.authEmail || byId<HTMLInputElement>("loginEmail").value;
  setManagedLockState(settings.policyLocked);

  const lastSyncAt = state?.lastSyncAt || "never";
  const policyVersion = state?.policy?.policy_version || "n/a";
  const platformMode = state?.policy?.platform_mode || "n/a";
  const healthTime = state?.lastHealthReportAt || "never";
  const healthStatus = state?.lastHealthReportStatus || "unknown";
  const refreshState = state?.hasRefreshToken ? "enabled" : "disabled";
  const queueDepth = Number(state?.telemetryQueueDepth || 0);
  const lastError = String(state?.lastError || "").trim() || "none";
  const managedState = settings.enterpriseManaged
    ? ` | Managed: yes | Policy locked: ${settings.policyLocked ? "yes" : "no"}`
    : " | Managed: no";
  setStatus(
    `Last sync: ${lastSyncAt} | Policy version: ${policyVersion} | Platform mode: ${platformMode}${managedState} | Session auto-refresh: ${refreshState} | Health report: ${healthStatus} @ ${healthTime} | Queue: ${queueDepth} | Last error: ${lastError}`
  );
}

async function saveSettings(): Promise<void> {
  const settings = await getSettings();
  if (settings.policyLocked) {
    setManagedLockState(true);
    setStatus("Settings are managed and locked by your administrator. Sign in and sync policy instead.");
    return;
  }
  const backendUrl = byId<HTMLInputElement>("backendUrl").value.trim().replace(/\/+$/, "");
  const tenantId = byId<HTMLInputElement>("tenantId").value.trim();
  const browser = normalizeBrowserType(byId<HTMLSelectElement>("browser").value);
  const browserProfile = byId<HTMLInputElement>("browserProfile").value.trim() || "default";
  const pilotHostname = byId<HTMLInputElement>("pilotHostname").value.trim();
  const pilotDeviceTypeRaw = byId<HTMLSelectElement>("pilotDeviceType").value.trim().toLowerCase();
  const pilotDeviceType = ["laptop", "desktop", "vm"].includes(pilotDeviceTypeRaw) ? pilotDeviceTypeRaw : "laptop";
  const pilotOsVersion = byId<HTMLInputElement>("pilotOsVersion").value.trim();

  await chrome.storage.local.set({
    [STORAGE_KEYS.backendUrl]: backendUrl,
    [STORAGE_KEYS.tenantId]: tenantId,
    [STORAGE_KEYS.browser]: browser,
    [STORAGE_KEYS.browserProfile]: browserProfile,
    [STORAGE_KEYS.pilotHostname]: pilotHostname,
    [STORAGE_KEYS.pilotDeviceType]: pilotDeviceType,
    [STORAGE_KEYS.pilotOsVersion]: pilotOsVersion,
  });
  setStatus("Settings saved. Syncing policy...");
  const syncResult = await chrome.runtime.sendMessage({ type: "SYNC_POLICY_NOW" }) as { ok?: boolean; error?: string };
  if (syncResult?.ok) {
    await loadSettingsIntoForm();
    return;
  }
  setStatus(`Settings saved. Policy sync failed: ${syncResult?.error || "unknown error"}`);
}

async function syncNow(): Promise<void> {
  setStatus("Syncing policy...");
  const syncResult = await chrome.runtime.sendMessage({ type: "SYNC_POLICY_NOW" }) as { ok?: boolean; error?: string };
  if (syncResult?.ok) {
    await loadSettingsIntoForm();
    return;
  }
  setStatus(`Policy sync failed: ${syncResult?.error || "unknown error"}`);
}

async function signIn(): Promise<void> {
  const backendUrl = byId<HTMLInputElement>("backendUrl").value.trim().replace(/\/+$/, "");
  const tenantId = byId<HTMLInputElement>("tenantId").value.trim();
  const email = byId<HTMLInputElement>("loginEmail").value.trim();
  const password = byId<HTMLInputElement>("loginPassword").value;
  if (!backendUrl) {
    setStatus("Backend URL is required before sign in.");
    return;
  }
  if (!email || !password) {
    setStatus("Enter login email/password to sign in.");
    return;
  }

  setStatus("Signing in...");
  const session = await signInWithCredentials({
    backendUrl,
    email,
    password,
    tenantId: tenantId || undefined,
  });
  byId<HTMLInputElement>("tenantId").value = session.tenantId;
  byId<HTMLInputElement>("accessToken").value = sessionLabel(Boolean(session.accessToken));
  byId<HTMLInputElement>("refreshToken").value = sessionLabel(Boolean(session.refreshToken));
  byId<HTMLInputElement>("loginPassword").value = "";

  setStatus(`Signed in. Session ready (auto-refresh enabled). Syncing policy...`);
  await syncNow();
}

document.addEventListener("DOMContentLoaded", () => {
  void loadSettingsIntoForm().catch((error) => setStatus(`Failed to load settings: ${String(error)}`));
  byId<HTMLButtonElement>("signInButton").addEventListener("click", () => {
    void signIn().catch((error) => setStatus(`Sign in failed: ${String(error)}`));
  });
  byId<HTMLButtonElement>("saveButton").addEventListener("click", () => {
    void saveSettings().catch((error) => setStatus(`Save failed: ${String(error)}`));
  });
  byId<HTMLButtonElement>("syncButton").addEventListener("click", () => {
    void syncNow().catch((error) => setStatus(`Sync failed: ${String(error)}`));
  });
});
