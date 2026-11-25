/** Types for settings-menu.mjs (the Settings menu, as FTR Command Center's settingsNav). */
export type SettingsItem = { href: string; label: string };
export type SettingsGroup = { label: string; items: SettingsItem[] };
export type JumpEntry = { title: string; sub: string; href: string };
export const SETTINGS_ENTRY: SettingsItem;
export const SETTINGS_GROUPS: SettingsGroup[];
export const SETTINGS_PERMISSIONS: Record<string, string[] | null>;
export function mayOpen(href: string, permissions: readonly string[] | null | undefined): boolean;
export function settingsNav(permissions: readonly string[] | null | undefined): SettingsGroup[];
export function isSettingsItemActive(pathname: string, href: string): boolean;
export function settingsJumpEntries(permissions: readonly string[] | null | undefined): JumpEntry[];
export function jumpMatches<T extends { title: string; sub: string }>(entries: T[], query: string, limit?: number): T[];
