import Link from "next/link";
import { Fragment } from "react";

import { GUIDE_HREF, GUIDE_INTRO, GUIDE_TOPICS, guideNeighbours, guideTopicHref, inlineParts, plainText } from "@/lib/guide";
import type { GuideBlock, GuideTopic } from "@/lib/guide";

/**
 * Settings → Guide: the administrator's guide (lib/guide), in FTR Command Center's Settings look (ftr-settings.css):
 * the head and crumbs of every Settings page, a table of contents on the left (above the page on a phone), and one
 * panel per section, its h2 with who may do it. Static: no data is fetched.
 */

export function GuideText({ text }: { text: string }) {
  return (
    <>
      {inlineParts(text).map((part, i) => {
        if (part.kind === "code") return <code key={i}>{part.text}</code>;
        if (part.kind === "b") return <strong key={i}>{part.text}</strong>;
        if (part.kind === "link")
          return (
            <Link key={i} href={part.href}>
              {part.text}
            </Link>
          );
        return <Fragment key={i}>{part.text}</Fragment>;
      })}
    </>
  );
}

export function GuideBlockView({ block }: { block: GuideBlock }) {
  switch (block.kind) {
    case "p":
      return (
        <p>
          <GuideText text={block.text} />
        </p>
      );
    case "list":
    case "steps": {
      const items = block.items.map((item, i) => (
        <li key={i}>
          <GuideText text={item} />
        </li>
      ));
      return block.kind === "list" ? <ul className="guide-list">{items}</ul> : <ol className="guide-list">{items}</ol>;
    }
    case "code":
      return (
        <figure className="guide-cmd">
          {block.caption ? (
            <figcaption className="muted small">
              <GuideText text={block.caption} />
            </figcaption>
          ) : null}
          <pre className="code">
            <code>{block.lines.join("\n")}</code>
          </pre>
        </figure>
      );
    case "table":
      return (
        <div className="tw">
          <table className={`guide-table cols-${block.head.length}`}>
            <thead>
              <tr>
                {block.head.map((cell, i) => (
                  <th key={i}>
                    <GuideText text={cell} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td key={j} data-label={plainText(block.head[j] ?? "")}>
                      <GuideText text={cell} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "note":
      return (
        <div className={`callout guide-note${block.tone === "warn" ? " warn" : ""}`} role="note">
          <GuideText text={block.text} />
        </div>
      );
  }
}

/** The table of contents: every topic, and the sections of the one open. */
export function GuideToc({ current }: { current?: string }) {
  return (
    <nav className="guide-toc" aria-label="Guide contents">
      <span className="set-label">Contents</span>
      <ol>
        {GUIDE_TOPICS.map((topic) => {
          const on = topic.slug === current;
          return (
            <li key={topic.slug}>
              <Link href={guideTopicHref(topic.slug)} className={on ? "on" : undefined} aria-current={on ? "page" : undefined}>
                {topic.title}
              </Link>
              {on ? (
                <ul>
                  {topic.sections.map((section) => (
                    <li key={section.id}>
                      <a href={`#${section.id}`}>{section.title}</a>
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/** One topic: its title and summary, then a panel per section. */
export function GuideArticle({ topic }: { topic: GuideTopic }) {
  const { previous, next } = guideNeighbours(topic.slug);
  return (
    <article className="guide-article" data-topic={topic.slug}>
      <div className="panel guide-intro">
        <h2>{topic.title}</h2>
        <p className="muted">
          <GuideText text={topic.summary} />
        </p>
      </div>
      {topic.sections.map((section) => (
        <section className="panel mt guide-section" id={section.id} key={section.id} aria-labelledby={`${section.id}-title`}>
          <h2 id={`${section.id}-title`}>
            <span>{section.title}</span>
            {section.who ? <span className="chip role">{section.who}</span> : null}
          </h2>
          {section.blocks.map((block, i) => (
            <GuideBlockView key={i} block={block} />
          ))}
        </section>
      ))}
      <div className="guide-pager mt">
        {previous ? (
          <Link className="btn ghost" href={guideTopicHref(previous.slug)}>
            ← {previous.title}
          </Link>
        ) : (
          <Link className="btn ghost" href={GUIDE_HREF}>
            ← Guide
          </Link>
        )}
        {next ? (
          <Link className="btn ghost" href={guideTopicHref(next.slug)}>
            {next.title} →
          </Link>
        ) : null}
      </div>
    </article>
  );
}

/** The guide's first page: for whom it is, and every topic with its summary. */
export function GuideIndex() {
  return (
    <div className="guide-article">
      <div className="panel guide-intro">
        <h2>Administrator&apos;s guide</h2>
        {GUIDE_INTRO.map((line, i) => (
          <p key={i} className={i ? undefined : "muted"}>
            <GuideText text={line} />
          </p>
        ))}
      </div>
      <ol className="guide-topics mt">
        {GUIDE_TOPICS.map((topic) => (
          <li key={topic.slug} className="panel">
            <Link href={guideTopicHref(topic.slug)}>
              <b>{topic.title}</b>
            </Link>
            <span className="muted small">
              <GuideText text={topic.summary} />
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** A Settings page of the guide: the head, the contents beside the page, the page. */
export function GuidePage({ current, children }: { current?: string; children: React.ReactNode }) {
  return (
    <div className="ftr-settings" data-ui="settings-guide">
      <div className="head compact">
        <div className="ht">
          <h1 className="serif">Guide</h1>
          <span className="crumbs">for administrators · everyone signed in can read it</span>
        </div>
      </div>
      <div className="guide-wrap">
        <GuideToc current={current} />
        <div className="guide-main">{children}</div>
      </div>
    </div>
  );
}
