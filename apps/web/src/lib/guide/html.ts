/**
 * The administrator's guide as one self-contained, printable HTML file (no script, no external file), from the same
 * data as the console pages. Written by scripts/build-guide-html.mjs; links between topics become links inside the file,
 * links to console pages become their names.
 */
import { GUIDE_HREF, GUIDE_INTRO, GUIDE_TOPICS } from "./index";
import { inlineParts } from "./inline";
import type { GuideBlock, GuideTopic } from "./types";

const escape = (text: string) =>
  String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

/** The anchor of a section in the one-file guide: unique across every topic. */
export function htmlAnchor(slug: string, section?: string): string {
  return section ? `${slug}--${section}` : slug;
}

function linkTarget(href: string): string | null {
  if (!href.startsWith(`${GUIDE_HREF}/`)) return null;
  const [path, section] = href.slice(GUIDE_HREF.length + 1).split("#");
  return `#${htmlAnchor(path, section)}`;
}

export function inlineHtml(text: string): string {
  return inlineParts(text)
    .map((part) => {
      if (part.kind === "code") return `<code>${escape(part.text)}</code>`;
      if (part.kind === "b") return `<strong>${escape(part.text)}</strong>`;
      if (part.kind === "link") {
        const target = linkTarget(part.href);
        return target ? `<a href="${escape(target)}">${escape(part.text)}</a>` : `<span class="page">${escape(part.text)}</span>`;
      }
      return escape(part.text);
    })
    .join("");
}

function blockHtml(block: GuideBlock): string {
  switch (block.kind) {
    case "p":
      return `<p>${inlineHtml(block.text)}</p>`;
    case "list":
      return `<ul>${block.items.map((item) => `<li>${inlineHtml(item)}</li>`).join("")}</ul>`;
    case "steps":
      return `<ol>${block.items.map((item) => `<li>${inlineHtml(item)}</li>`).join("")}</ol>`;
    case "code":
      return `<figure class="cmd">${block.caption ? `<figcaption>${inlineHtml(block.caption)}</figcaption>` : ""}<pre><code>${block.lines.map(escape).join("\n")}</code></pre></figure>`;
    case "table":
      return `<table><thead><tr>${block.head.map((h) => `<th>${inlineHtml(h)}</th>`).join("")}</tr></thead><tbody>${block.rows
        .map((row) => `<tr>${row.map((cell) => `<td>${inlineHtml(cell)}</td>`).join("")}</tr>`)
        .join("")}</tbody></table>`;
    case "note":
      return `<p class="note ${block.tone}">${inlineHtml(block.text)}</p>`;
  }
}

function topicHtml(topic: GuideTopic, n: number): string {
  const sections = topic.sections
    .map(
      (section) =>
        `<section id="${htmlAnchor(topic.slug, section.id)}"><h3>${escape(section.title)}${section.who ? ` <span class="who">${escape(section.who)}</span>` : ""}</h3>${section.blocks
          .map(blockHtml)
          .join("")}</section>`,
    )
    .join("");
  return `<article id="${htmlAnchor(topic.slug)}"><h2><span class="n">${n}.</span> ${escape(topic.title)}</h2><p class="summary">${inlineHtml(topic.summary)}</p>${sections}</article>`;
}

const CSS = `
:root { --text: #17212a; --muted: #566573; --line: #d5dce1; --brand: #0b6b86; --soft: #f1f4f6; --warn: #9a6700; }
* { box-sizing: border-box; }
body { margin: 0; color: var(--text); background: #fff; font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 820px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 28px; margin: 0 0 4px; }
h2 { font-size: 22px; margin: 0 0 4px; padding-top: 8px; }
h2 .n { color: var(--muted); }
h3 { font-size: 16px; margin: 26px 0 8px; }
a { color: var(--brand); }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em; }
code { background: var(--soft); border-radius: 4px; padding: 0 4px; overflow-wrap: anywhere; }
pre { background: var(--soft); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; white-space: pre-wrap; word-break: break-all; margin: 6px 0 0; }
pre code { background: none; padding: 0; }
figure.cmd { margin: 12px 0; }
figcaption { color: var(--muted); font-size: 13px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 14px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
th { color: var(--muted); font-size: 13px; border-bottom-color: var(--text); }
.summary, .lead { color: var(--muted); }
.who { display: inline-block; margin-left: 6px; padding: 1px 8px; border: 1px solid var(--line); border-radius: 6px; color: var(--muted); font-size: 12px; font-weight: 500; vertical-align: middle; }
.note { padding: 10px 14px; border-radius: 10px; border: 1px solid rgba(11, 107, 134, .3); background: rgba(11, 107, 134, .06); }
.note.warn { border-color: rgba(154, 103, 0, .4); background: rgba(154, 103, 0, .07); }
.page { font-weight: 600; }
nav.toc { margin: 24px 0 8px; padding: 14px 18px; border: 1px solid var(--line); border-radius: 12px; background: var(--soft); }
nav.toc ol { margin: 6px 0 0; padding-left: 22px; }
nav.toc li { margin: 3px 0; }
nav.toc ul { margin: 2px 0 6px; padding-left: 18px; color: var(--muted); font-size: 13.5px; }
article { border-top: 2px solid var(--text); margin-top: 40px; padding-top: 12px; }
footer { margin-top: 48px; color: var(--muted); font-size: 13px; }
@media print {
  body { font-size: 11pt; }
  main { max-width: none; padding: 0; }
  article { break-before: page; border-top: 0; margin-top: 0; }
  section, figure, table, .note { break-inside: avoid; }
  a { color: inherit; text-decoration: none; }
}
`;

/** The whole guide as one HTML document. */
export function guideHtml(options: { version?: string; generatedAt?: string } = {}): string {
  const version = options.version ? `Hawk AI ${options.version}` : "Hawk AI";
  const toc = GUIDE_TOPICS.map(
    (topic) =>
      `<li><a href="#${htmlAnchor(topic.slug)}">${escape(topic.title)}</a><ul>${topic.sections
        .map((section) => `<li><a href="#${htmlAnchor(topic.slug, section.id)}">${escape(section.title)}</a></li>`)
        .join("")}</ul></li>`,
  ).join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hawk AI administrator's guide</title>
<style>${CSS}</style>
</head>
<body>
<main>
<h1>Hawk AI administrator's guide</h1>
<p class="lead">${escape(version)}${options.generatedAt ? ` · ${escape(options.generatedAt)}` : ""} · the same guide as Settings → Guide in the console</p>
${GUIDE_INTRO.map((line) => `<p>${inlineHtml(line)}</p>`).join("\n")}
<nav class="toc" aria-label="Contents"><b>Contents</b><ol>${toc}</ol></nav>
${GUIDE_TOPICS.map((topic, i) => topicHtml(topic, i + 1)).join("\n")}
<footer>${escape(version)} administrator's guide.</footer>
</main>
</body>
</html>
`;
}
