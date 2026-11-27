"use client";

/**
 * What Settings → General, Branding, Email (SMTP) and About read and write (app/api/routers/settings_console.py), and
 * the two things every page of the console shares with them: the branding (the menu's name and logo, the browser
 * icon, the look) and the permissions the Settings menu is filtered by.
 */

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { API_BASE_URL } from "@/lib/api-url";
import { getSession, SESSION_CHANGE_EVENT } from "@/lib/auth";
import { applyTheme, currentTheme } from "@/lib/theme";

export type BrandingView = {
  appName: string;
  tagline: string;
  organisationName: string;
  accent: string;
  mode: "light" | "dark" | "system";
  logo: string | null;
  icon: string | null;
  logoBytes: number;
  iconBytes: number;
  limits: { logo: number; icon: number };
};

export type BrandingPatch = Partial<Pick<BrandingView, "appName" | "tagline" | "organisationName" | "accent" | "mode">> & {
  logo?: { upload: string } | null;
  icon?: { upload: string } | null;
};

export type SmtpSettings = {
  host: string;
  port: number;
  secure: boolean;
  requireAuth: boolean;
  rejectUnauthorized: boolean;
  user: string;
  fromName: string;
  fromAddress: string;
  passwordSet: boolean;
};

export type SmtpView = {
  /** False for a workspace admin who is not one of the server's administrators: shown read-only. */
  mayChange?: boolean;
  readOnlyNote?: string;
  smtp: SmtpSettings;
  source: "settings" | "environment" | "";
  verified: boolean;
  verifiedAt: string | null;
  passwordReset: "everyone" | "not-admins" | "off";
  reset: { ready: boolean; policy: string; missing: string[] };
  publicUrl: string;
};

export type GeneralView = { serverAddress: string; webOrigin: string; trustedHosts: string[] };

export type AboutView = {
  appName: string;
  version: string;
  versionLabel: string;
  licence: { active: boolean; until: string; daysLeft: number; trial?: boolean; installationId?: string; activation: { org: string; expires: string; at?: string } | null; message: string };
  terms: { version: string; accepted: boolean; at: string | null; acceptanceId?: string | null; scope?: "organisation" | "user" | null; canManage?: boolean };
  organisationName: string;
  changelog: string;
  notices: { name: string; text: string } | null;
  canUpdate: boolean;
  /** Where the data is (Settings → Compliance). */
  dataResidency?: { location: string; region: string; statement: string };
};

export const DEFAULT_BRANDING: BrandingView = {
  appName: "Hawk AI",
  tagline: "AI control plane",
  organisationName: "",
  accent: "",
  mode: "light",
  logo: null,
  icon: null,
  logoBytes: 0,
  iconBytes: 0,
  limits: { logo: 200 * 1024, icon: 100 * 1024 },
};

/** A kept image's address (/branding/logo?v=…), on the API. */
export const brandingImage = (path: string | null): string | null => (path ? `${API_BASE_URL}${path}` : null);

export const BRANDING_EVENT = "hawk-branding-change";
let brandingNow: BrandingView | null = null;
let brandingLoad: Promise<BrandingView> | null = null;

/** Applied to the page: the browser icon, the look (light, dark or the device's) and the accent colour. */
export function applyBranding(b: BrandingView): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  // This browser's own choice (the account menu) comes first; the organisation's look is the default (lib/theme.ts).
  applyTheme(currentTheme(b.mode));
  if (b.accent) root.style.setProperty("--brand-accent", b.accent);
  else root.style.removeProperty("--brand-accent");
  const icon = brandingImage(b.icon);
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"][data-branding]');
  if (icon) {
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      link.dataset.branding = "1";
      document.head.append(link);
    }
    link.href = icon;
  } else link?.remove();
}

export function setBranding(b: BrandingView): void {
  brandingNow = b;
  applyBranding(b);
  if (typeof window !== "undefined") window.dispatchEvent(new CustomEvent(BRANDING_EVENT, { detail: b }));
}

/** The branding, read once per page load (it is open to everyone, as FTR's /api/branding). */
export function useBranding(): BrandingView {
  const [b, setB] = useState<BrandingView>(brandingNow ?? DEFAULT_BRANDING);
  useEffect(() => {
    const on = (event: Event) => setB((event as CustomEvent<BrandingView>).detail);
    window.addEventListener(BRANDING_EVENT, on);
    if (!brandingNow) {
      brandingLoad ??= api.getBranding().then((view) => ({ ...DEFAULT_BRANDING, ...view }));
      brandingLoad.then(setBranding, () => {
        brandingLoad = null;
      });
    } else {
      setB(brandingNow);
      applyBranding(brandingNow);
    }
    return () => window.removeEventListener(BRANDING_EVENT, on);
  }, []);
  return b;
}

/**
 * What GET /settings/me answers: the person's role and permissions in this workspace, and whether they are one of the
 * server's administrators (the owners and admins of its first workspace), who alone change the settings of the whole
 * server (sign-in rules, compliance, email, HTTPS, network, updates, backups, hands-off, branding, the licence).
 */
export type SettingsMe = { role: string; permissions: string[]; installationAdmin?: boolean; readOnlyNote?: string };

/** The note shown beside a setting of the whole server to a workspace admin who may read it but not change it. */
export const SET_BY_SERVER = "Set by the server's administrators.";

const meByTenant = new Map<string, Promise<SettingsMe>>();

function useSettingsMe(): SettingsMe | null {
  const [me, setMe] = useState<SettingsMe | null>(null);
  useEffect(() => {
    let live = true;
    const read = () => {
      const session = getSession();
      const key = `${session?.tenantId ?? ""}:${session?.user?.email ?? ""}`;
      if (!session?.tenantId) return;
      let pending = meByTenant.get(key);
      if (!pending) {
        pending = api.getSettingsMe();
        meByTenant.set(key, pending);
        pending.catch(() => meByTenant.delete(key));
      }
      pending.then((m) => live && setMe(m), () => live && setMe({ role: "", permissions: [], installationAdmin: false }));
    };
    read();
    window.addEventListener(SESSION_CHANGE_EVENT, read);
    return () => {
      live = false;
      window.removeEventListener(SESSION_CHANGE_EVENT, read);
    };
  }, []);
  return me;
}

/** The permissions of the person signed in (null while they are read), for the Settings menu and Jump to. */
export function useMyPermissions(): string[] | null {
  return useSettingsMe()?.permissions ?? null;
}

/**
 * Whether the person may change the settings of the whole server (null while it is read). An older server that does
 * not say counts as yes: the server refuses a change it does not allow anyway.
 */
export function useInstallationAdmin(): boolean | null {
  const me = useSettingsMe();
  return me === null ? null : me.installationAdmin !== false;
}

/** A file, as base64 (FTR's fileToBase64). */
export const fileToBase64 = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] ?? "");
    reader.onerror = () => reject(new Error(`${file.name} could not be read.`));
    reader.readAsDataURL(file);
  });
