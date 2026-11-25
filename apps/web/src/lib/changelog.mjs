/**
 * About's version log, as FTR Command Center's (ftr-cc-dashboard CC-01.116.00, public/js/about.js): CHANGELOG.md as
 * blocks — headings, lists (one level in), bold and code only — and its versions, the latest three open and the
 * earlier ones ten at a time. Returned as data (not HTML) so the page renders it with React, which escapes the text.
 */

export const SHOWN_OPEN = 3;
export const MORE = 10;

/** The versions of a CHANGELOG.md: each "## " section, in the file's order (newest first). */
export function splitVersions(text) {
  return String(text || "")
    .replace(/\r\n/g, "\n")
    .replace(/^# .*\n/, "")
    .split(/\n(?=## )/)
    .filter((part) => part.startsWith("## "))
    .map((part) => {
      const lines = part.split("\n");
      return { title: lines[0].replace(/^## /, "").trim(), body: lines.slice(1).join("\n") };
    });
}

/**
 * FTR's md(): blocks first (a heading, a list item with how far in it sits, or a paragraph); a line that only carries
 * on the one before it (a long item wrapped in the file) is joined to it. Lists are nested one level.
 */
export function mdBlocks(text) {
  const blocks = [];
  for (const line of String(text || "").split("\n")) {
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    const item = /^(\s*)[-*]\s+(.*)$/.exec(line);
    const last = blocks[blocks.length - 1];
    if (heading) blocks.push({ kind: "h", level: heading[1].length + 1, text: heading[2] });
    else if (item) blocks.push({ kind: "li", depth: item[1].length >= 2 ? 1 : 0, text: item[2] });
    else if (!line.trim()) blocks.push({ kind: "gap" });
    else if (last && (last.kind === "li" || last.kind === "p")) last.text += ` ${line.trim()}`;
    else blocks.push({ kind: "p", text: line.trim() });
  }
  // Lists: consecutive items, each top-level item with the items one level in under it.
  const out = [];
  let list = null;
  for (const block of blocks) {
    if (block.kind === "li") {
      if (!list) {
        list = { kind: "ul", items: [] };
        out.push(list);
      }
      const parent = list.items[list.items.length - 1];
      if (block.depth === 1 && parent) parent.children.push({ text: block.text });
      else list.items.push({ text: block.text, children: [] });
      continue;
    }
    if (block.kind === "gap") continue;
    list = null;
    out.push(block);
  }
  return out;
}

/** Inline marks: **bold** and `code`, as [{kind: "text"|"b"|"code", text}]. */
export function inline(text) {
  const parts = [];
  const pattern = /\*\*([^*]+)\*\*|`([^`]+)`/g;
  let at = 0;
  let found;
  const source = String(text || "");
  while ((found = pattern.exec(source))) {
    if (found.index > at) parts.push({ kind: "text", text: source.slice(at, found.index) });
    parts.push(found[1] !== undefined ? { kind: "b", text: found[1] } : { kind: "code", text: found[2] });
    at = found.index + found[0].length;
  }
  if (at < source.length) parts.push({ kind: "text", text: source.slice(at) });
  return parts;
}
