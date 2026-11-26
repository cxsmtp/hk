/** The guide's three text marks: `code`, **bold** and [a link](/settings/…). Everything else is plain text. */
export type InlinePart = { kind: "text" | "code" | "b"; text: string } | { kind: "link"; text: string; href: string };

const MARK = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)\s]+\))/g;

export function inlineParts(text: string): InlinePart[] {
  const source = String(text ?? "");
  const parts: InlinePart[] = [];
  let last = 0;
  for (const match of source.matchAll(MARK)) {
    const token = match[0];
    const at = match.index ?? 0;
    if (at > last) parts.push({ kind: "text", text: source.slice(last, at) });
    if (token.startsWith("`")) parts.push({ kind: "code", text: token.slice(1, -1) });
    else if (token.startsWith("**")) parts.push({ kind: "b", text: token.slice(2, -2) });
    else {
      const close = token.indexOf("](");
      parts.push({ kind: "link", text: token.slice(1, close), href: token.slice(close + 2, -1) });
    }
    last = at + token.length;
  }
  if (last < source.length) parts.push({ kind: "text", text: source.slice(last) });
  return parts;
}

/** The text without its marks. */
export function plainText(text: string): string {
  return inlineParts(text)
    .map((part) => part.text)
    .join("");
}
