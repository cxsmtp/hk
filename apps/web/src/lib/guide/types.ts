/**
 * The administrator's guide (Settings → Guide), as typed data: one topic per page, each in sections with a left table of
 * contents. The same data renders the console pages (components/guide/guide-view.tsx) and the printable HTML file
 * (lib/guide/html.ts, scripts/build-guide-html.mjs). Every fact is taken from the code: tests/guide.test.mjs checks that
 * each setting, command and page it names exists.
 *
 * Text is plain, with three marks only: `code` (a command, a setting or a file), **bold** and [a link](/settings/…).
 */

/** One piece of a topic: a paragraph, a list, numbered steps, commands to type, a table or a note. */
export type GuideBlock =
  | { kind: "p"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "steps"; items: string[] }
  | { kind: "code"; lines: string[]; caption?: string }
  | { kind: "table"; head: string[]; rows: string[][] }
  | { kind: "note"; tone: "info" | "warn"; text: string };

/** A section of a topic: its anchor (unique in the topic), its title, and who can do it when not everyone. */
export type GuideSection = {
  id: string;
  title: string;
  /** Who can do what this section describes, when not everyone (e.g. "Owners and admins"): a chip beside the title. */
  who?: string;
  blocks: GuideBlock[];
};

/** A topic: one page of the guide. */
export type GuideTopic = {
  slug: string;
  title: string;
  /** One line under the title, and on the guide's first page. */
  summary: string;
  sections: GuideSection[];
};
