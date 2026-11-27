/**
 * The console's look: light (the default), dark, or the device's own (system). Each browser keeps its own choice
 * (localStorage, hawk-theme); without one, the organisation's default from Settings → Branding applies, and light
 * before that is known. app/layout.tsx sets it before the page is drawn (THEME_BOOT), so a page never flashes dark.
 */

export type ThemeChoice = "light" | "dark" | "system";

export const THEME_KEY = "hawk-theme";
export const THEME_EVENT = "hawk-theme-change";
export const THEME_CHOICES: readonly ThemeChoice[] = ["light", "dark", "system"];

const isChoice = (value: unknown): value is ThemeChoice => value === "light" || value === "dark" || value === "system";

/** This browser's choice, or null when it made none (or storage is unavailable). */
export function readThemeChoice(): ThemeChoice | null {
  try {
    const value = window.localStorage.getItem(THEME_KEY);
    return isChoice(value) ? value : null;
  } catch {
    return null;
  }
}

/** Light or dark, for a choice (system: the device's setting). */
export function resolveTheme(choice: ThemeChoice): "light" | "dark" {
  if (choice !== "system") return choice;
  try {
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

/** The look to show: this browser's choice, else the organisation's default, else light. */
export function currentTheme(organisationDefault?: string | null): "light" | "dark" {
  const own = readThemeChoice();
  if (own) return resolveTheme(own);
  return resolveTheme(isChoice(organisationDefault) ? organisationDefault : "light");
}

export function applyTheme(theme: "light" | "dark"): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

/** Keep this browser's choice and show it now. */
export function saveThemeChoice(choice: ThemeChoice): void {
  try {
    window.localStorage.setItem(THEME_KEY, choice);
  } catch {
    // Storage unavailable (a private window): the choice lasts for this page only.
  }
  applyTheme(choice === "system" ? resolveTheme("system") : choice);
  window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: choice }));
}

/** Run before the page is drawn (an inline script in <head>): the remembered look, or light. */
export const THEME_BOOT = `(function(){try{var c=localStorage.getItem(${JSON.stringify(THEME_KEY)});var d=c==="dark"||(c==="system"&&window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches);var t=d?"dark":"light";document.documentElement.dataset.theme=t;document.documentElement.style.colorScheme=t;}catch(e){document.documentElement.dataset.theme="light";}})();`;
