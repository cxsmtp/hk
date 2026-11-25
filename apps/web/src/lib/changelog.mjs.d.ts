/** Types for changelog.mjs (About's version log, as FTR Command Center's public/js/about.js). */
export type Version = { title: string; body: string };
export type InlinePart = { kind: "text" | "b" | "code"; text: string };
export type ListItem = { text: string; children: { text: string }[] };
export type MdBlock = { kind: "h"; level: number; text: string } | { kind: "p"; text: string } | { kind: "ul"; items: ListItem[] };
export const SHOWN_OPEN: number;
export const MORE: number;
export function splitVersions(text: string): Version[];
export function mdBlocks(text: string): MdBlock[];
export function inline(text: string): InlinePart[];
