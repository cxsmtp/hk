import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { registerProductionAliases } from "./fixtures/ts-alias-hooks.mjs";
import { mayOpen, settingsJumpEntries, settingsNav, SETTINGS_PERMISSIONS } from "../src/lib/settings-menu.mjs";

// The administrator's guide (Settings → Guide): its data (src/lib/guide), the page component, the printable file, and
// that every setting, command, page and address it names exists in the code it describes.
registerProductionAliases();
const { createElement } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
const guide = await import("../src/lib/guide/index.ts");
const { guideHtml, htmlAnchor } = await import("../src/lib/guide/html.ts");
const view = await import("../src/components/guide/guide-view.tsx");

const { GUIDE_TOPICS, GUIDE_INTRO, GUIDE_HREF, guideTopic, guideJumpEntries, inlineParts } = guide;
const repo = (path) => readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");
const exists = (path) => existsSync(new URL(`../../../${path}`, import.meta.url));
const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

/** Every piece of text in the guide (with its marks), and every line of every command block. */
function texts() {
  const out = [...GUIDE_INTRO];
  const lines = [];
  for (const topic of GUIDE_TOPICS) {
    out.push(topic.summary);
    for (const section of topic.sections) {
      for (const block of section.blocks) {
        if (block.kind === "p" || block.kind === "note") out.push(block.text);
        if (block.kind === "list" || block.kind === "steps") out.push(...block.items);
        if (block.kind === "table") out.push(...block.head, ...block.rows.flat());
        if (block.kind === "code") {
          lines.push(...block.lines);
          if (block.caption) out.push(block.caption);
        }
      }
    }
  }
  return { out, lines };
}
const codeSpans = () =>
  texts()
    .out.flatMap((text) => inlineParts(text))
    .filter((part) => part.kind === "code")
    .map((part) => part.text);
const links = () =>
  texts()
    .out.flatMap((text) => inlineParts(text))
    .filter((part) => part.kind === "link");

test("twelve topics, each with a title, a summary and sections; slugs and anchors unique and safe", () => {
  assert.deepEqual(
    GUIDE_TOPICS.map((t) => t.slug),
    ["install", "first-sign-in", "people-and-access", "https", "email", "backups", "updates", "licence", "audit-and-evidence", "network", "self-check-and-help", "troubleshooting"],
  );
  const slug = /^[a-z0-9]+(-[a-z0-9]+)*$/;
  for (const topic of GUIDE_TOPICS) {
    assert.match(topic.slug, slug);
    assert.ok(topic.title && topic.summary && topic.sections.length >= 2, topic.slug);
    const ids = topic.sections.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length, `${topic.slug}: section ids repeat`);
    for (const section of topic.sections) {
      assert.match(section.id, slug, `${topic.slug}#${section.id}`);
      assert.ok(section.title && section.blocks.length, `${topic.slug}#${section.id}`);
      // A section id never takes the id of a heading in the page (each section's h2 is "<id>-title").
      assert.ok(!ids.includes(`${section.id}-title`));
    }
    assert.equal(guideTopic(topic.slug), topic);
  }
  // In the one-file guide every anchor is unique across topics.
  const anchors = GUIDE_TOPICS.flatMap((t) => [htmlAnchor(t.slug), ...t.sections.map((s) => htmlAnchor(t.slug, s.id))]);
  assert.equal(new Set(anchors).size, anchors.length);
  assert.equal(guideTopic("nope"), undefined);
});

test("every topic renders on its page: title, each section with its anchor, who may do it, commands and tables", () => {
  for (const topic of GUIDE_TOPICS) {
    const html = renderToStaticMarkup(createElement(view.GuidePage, { current: topic.slug }, createElement(view.GuideArticle, { topic })));
    assert.match(html, /class="ftr-settings" data-ui="settings-guide"/);
    assert.ok(html.includes(`data-topic="${topic.slug}"`), topic.slug);
    for (const section of topic.sections) {
      assert.ok(html.includes(`id="${section.id}"`), `${topic.slug}#${section.id}`);
      // The contents on the left link to each section of the topic open.
      assert.ok(html.includes(`href="#${section.id}"`), `${topic.slug}: toc #${section.id}`);
      if (section.who) assert.ok(html.includes(`<span class="chip role">${section.who.replace(/&/g, "&amp;")}</span>`), section.who);
    }
    // Every topic in the contents, the one open marked.
    for (const other of GUIDE_TOPICS) assert.ok(html.includes(`href="${GUIDE_HREF}/${other.slug}"`), other.slug);
    assert.ok(html.includes('aria-current="page"'));
    for (const section of topic.sections)
      for (const block of section.blocks) {
        if (block.kind === "code") assert.ok(html.includes("<pre class=\"code\">"));
        if (block.kind === "table") assert.ok(html.includes(`<table class="guide-table cols-${block.head.length}">`) && html.includes(`data-label="`));
      }
    // No mark is left unrendered.
    assert.ok(!/`|\*\*|\]\(/.test(html.replace(/<pre[\s\S]*?<\/pre>/g, "")), topic.slug);
  }
  const first = renderToStaticMarkup(createElement(view.GuidePage, null, createElement(view.GuideIndex)));
  for (const topic of GUIDE_TOPICS) assert.ok(first.includes(`href="${GUIDE_HREF}/${topic.slug}"`) && first.includes(topic.title.replace(/'/g, "&#x27;")));
});

test("the page component is one page per topic, made at build time, in FTR's Settings look", () => {
  const page = source("app/settings/guide/[topic]/page.tsx");
  assert.match(page, /generateStaticParams/);
  assert.match(page, /dynamicParams = false/);
  assert.match(page, /notFound\(\)/);
  assert.ok(page.includes('import "../../ftr-settings.css"') && source("app/settings/guide/page.tsx").includes('import "../ftr-settings.css"'));
  const css = source("app/settings/ftr-settings.css");
  for (const rule of [".ftr-settings .guide-wrap", ".ftr-settings .guide-toc", "@media (max-width: 1100px)", "@media (max-width: 600px)"]) assert.ok(css.includes(rule), rule);
});

test("Guide is in the Settings menu under System, by Get help and About, for everyone; Jump to and Get help lead to it", () => {
  const ALL = ["settings.manage", "support.manage"];
  const system = settingsNav(ALL).find((g) => g.label === "System").items.map((i) => i.label);
  assert.deepEqual(system.slice(-3), ["Get help", "Guide", "About"]);
  assert.equal(SETTINGS_PERMISSIONS["/settings/guide"], null);
  assert.ok(mayOpen("/settings/guide", []) && mayOpen("/settings/guide", ["dashboard.view"]));
  assert.ok(settingsJumpEntries(ALL).some((e) => e.href === "/settings/guide" && e.sub === "Settings · System"));
  // Jump to (Ctrl K) lists the guide and each topic for everyone, whatever their role.
  const entries = guideJumpEntries();
  assert.equal(entries[0].href, GUIDE_HREF);
  for (const topic of GUIDE_TOPICS) assert.ok(entries.some((e) => e.href === `${GUIDE_HREF}/${topic.slug}`), topic.slug);
  assert.match(source("components/jump-to.tsx"), /\.\.\.guideJumpEntries\(\)/);
  for (const page of ["app/help/page.tsx", "app/settings/help/page.tsx"]) assert.match(source(page), /href=\{GUIDE_HREF\} data-guide-link/, page);
});

// Words in `code` that are not settings: the hands-off replies.
const NOT_SETTINGS = new Set(["PAUSE", "RESUME", "RUN", "STATUS", "STOP", "SOLVED"]);

test("every setting the guide names exists in deploy/.env.example, deploy/compose.yaml, deploy/install.sh or the API's config", () => {
  const corpus = [repo("deploy/.env.example"), repo("deploy/compose.yaml"), repo("deploy/install.sh")].join("\n");
  const config = repo("apps/api/app/core/config.py");
  const names = new Set();
  for (const span of codeSpans()) {
    const m = /^([A-Z][A-Z0-9_]+)(=.*)?$/.exec(span);
    if (m && !NOT_SETTINGS.has(m[1])) names.add(m[1]);
  }
  for (const line of texts().lines) for (const m of line.matchAll(/-e ([A-Z][A-Z0-9_]+)=/g)) names.add(m[1]);
  assert.ok(names.size > 60, `only ${names.size} settings found`);
  for (const name of names) {
    const known = new RegExp(`\\b${name}\\b`).test(corpus) || new RegExp(`^\\s+${name.toLowerCase()}: `, "m").test(config);
    assert.ok(known, `${name} is not a setting of Hawk AI`);
  }
});

test("defaults in the settings tables are deploy/.env.example's, and the dates and times are the code's", () => {
  const example = Object.fromEntries(
    repo("deploy/.env.example")
      .split("\n")
      .map((line) => /^([A-Z][A-Z0-9_]+)=(.*)$/.exec(line))
      .filter(Boolean)
      .map((m) => [m[1], m[2]]),
  );
  let checked = 0;
  for (const topic of GUIDE_TOPICS)
    for (const section of topic.sections)
      for (const block of section.blocks) {
        if (block.kind !== "table" || block.head[1] !== "Default") continue;
        for (const [name, value] of block.rows) {
          const key = /^`([A-Z][A-Z0-9_]+)`$/.exec(name)?.[1];
          const given = /^`([^`]+)`$/.exec(value)?.[1];
          if (key && given && example[key]) {
            assert.equal(given, example[key], `${key}: the guide says ${given}, deploy/.env.example ${example[key]}`);
            checked += 1;
          }
        }
      }
  assert.ok(checked >= 10, `${checked} defaults checked`);
  const all = texts().out.join("\n");
  assert.match(repo("apps/api/app/services/activation_service.py"), /PRODUCT_DEADLINE = "2027-02-01T00:00:00.000Z"/);
  assert.match(all, /31 January 2027/);
  assert.match(repo("apps/api/app/services/activation_service.py"), /WARN_DAYS = 30/);
  assert.match(repo("deploy/.env.example"), /UPDATE_START_TIMEOUT_SECONDS=150/);
  assert.match(all, /within 150 seconds/);
  assert.match(repo("apps/api/app/services/first_run_service.py"), /DEFAULT_ADMIN_EMAIL = "admin@hawk.local"/);
  assert.match(repo("apps/api/app/services/passwords.py"), /MIN_PASSWORD_LENGTH = 12/);
  assert.match(repo("apps/api/app/services/account_security.py"), /LOCK_SECONDS = 15 \* 60/);
  assert.match(repo("apps/api/app/core/config.py"), /session_idle_minutes: int = 480/);
  assert.match(all, /not used for 8 hours/);
});

test("every command the guide gives exists: CLI modules and their flags, scripts, tools and compose services", () => {
  const services = new Set([...repo("deploy/compose.yaml").split("\nservices:\n")[1].matchAll(/^  ([a-z]+):$/gm)].map((m) => m[1]));
  assert.ok(services.has("api") && services.has("worker") && services.has("beat") && services.has("updater"));
  const all = [...codeSpans(), ...texts().lines, ...texts().out];
  let modules = 0;
  for (const line of all) {
    for (const m of line.matchAll(/python3? -m app\.cli\.([a-z_]+)((?: [^\s`]+)*)/g)) {
      const file = `apps/api/app/cli/${m[1]}.py`;
      assert.ok(exists(file), file);
      for (const flag of m[2].match(/--[a-z-]+/g) ?? []) assert.ok(repo(file).includes(flag), `${file} has no ${flag}`);
      modules += 1;
    }
    for (const m of line.matchAll(/\b((?:tools|deploy|scripts)\/[\w./-]+\.(?:py|sh|mjs))/g)) assert.ok(exists(m[1]), m[1]);
    // In a command itself (a `code` span or a command block line), not in the sentence around it.
    const compose = !line.includes("`") && /docker compose -f deploy\/compose\.yaml (exec|run|stop|restart|logs|ps|up|down)((?: \S+)*)/.exec(line);
    if (compose) {
      const words = compose[2].replace(/<[^>]*>/g, "x").trim().split(/\s+/).filter(Boolean);
      const named = [];
      for (let i = 0; i < words.length; i += 1) {
        if (words[i] === "-e" || words[i] === "--tail") i += 1;
        else if (!words[i].startsWith("-")) named.push(words[i]);
      }
      const wanted = compose[1] === "exec" || compose[1] === "run" ? named.slice(0, 1) : ["up", "down", "ps"].includes(compose[1]) ? [] : named;
      for (const service of wanted) assert.ok(services.has(service), `${line}: no service ${service}`);
    }
  }
  assert.ok(modules >= 10, `${modules} CLI commands`);
  for (const cli of ["reset_admin", "https", "restore", "backup", "audit_verify", "integrity"]) assert.ok(all.some((l) => l.includes(`app.cli.${cli}`)), cli);
  assert.ok(all.some((l) => l === "sudo deploy/install.sh"));
  // The restore's dry run, then --yes after stopping api, worker and beat: as app/cli/restore.py prints it.
  const restore = repo("apps/api/app/cli/restore.py");
  assert.ok(restore.includes("docker compose -f deploy/compose.yaml stop api worker beat"));
  assert.ok(texts().lines.includes("docker compose -f deploy/compose.yaml stop api worker beat"));
  assert.ok(repo("apps/api/app/cli/https.py").includes("docker compose -f deploy/compose.yaml exec api python -m app.cli.https both"));
  // The containers see BACKUP_DIR as /backups (the path the restore commands use).
  assert.match(repo("deploy/compose.yaml"), /BACKUP_DIR: \/backups/);
});

test("every page and address the guide links to exists", () => {
  for (const link of links()) {
    if (link.href.startsWith(`${GUIDE_HREF}/`)) {
      const [slug, section] = link.href.slice(GUIDE_HREF.length + 1).split("#");
      const topic = guideTopic(slug);
      assert.ok(topic, link.href);
      if (section) assert.ok(topic.sections.some((s) => s.id === section), link.href);
    } else {
      assert.match(link.href, /^\/settings\/[a-z-]+$/, link.href);
      assert.ok(existsSync(new URL(`../src/app${link.href}/page.tsx`, import.meta.url)), link.href);
    }
  }
  const spans = codeSpans();
  assert.ok(spans.includes("/.well-known/hawk-evidence-keys.json"));
  assert.match(repo("apps/api/app/services/evidence_signing.py"), /\/\.well-known\/hawk-evidence-keys\.json/);
  const main = repo("apps/api/app/main.py");
  for (const span of spans.filter((s) => s.startsWith("/api/health"))) assert.ok(main.includes(`@app.get("${span.slice(4)}")`), span);
  assert.match(repo("apps/api/app/services/https_proxy.py"), /handle_path \/api\/\*/);
});

test("the printable file: one self-contained HTML document with every topic, its contents and working anchors", () => {
  const html = guideHtml({ version: "HK-00.02.01", generatedAt: "2026-11-26" });
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /<meta name="viewport"/);
  assert.ok(!/<script|<link |src="http|@import/i.test(html), "nothing loaded from outside");
  assert.ok(html.includes("HK-00.02.01"));
  const ids = [...html.matchAll(/ id="([^"]+)"/g)].map((m) => m[1]);
  assert.equal(new Set(ids).size, ids.length, "ids repeat");
  for (const m of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.includes(m[1]), `#${m[1]}`);
  for (const topic of GUIDE_TOPICS) {
    assert.ok(ids.includes(topic.slug));
    for (const section of topic.sections) assert.ok(ids.includes(`${topic.slug}--${section.id}`));
  }
  // Console links become page names; guide links stay inside the file.
  assert.ok(!html.includes('href="/settings'));
  assert.match(html, /<span class="page">Settings → HTTPS<\/span>/);
  assert.ok(repo("apps/web/scripts/build-guide-html.mjs").includes("process.argv[2]"));
});

test("the guide ships as console pages, not as Markdown files", () => {
  for (const path of ["apps/web/src/lib/guide", "apps/web/src/app/settings/guide"]) assert.ok(exists(path));
  assert.ok(!exists("docs/guide.md") && !exists("apps/web/src/lib/guide/README.md"));
});
