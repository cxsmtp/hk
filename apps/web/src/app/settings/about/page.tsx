"use client";

import "../ftr-settings.css";

import Link from "next/link";
import { Fragment, useEffect, useRef, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { termsCopyStatus } from "@/lib/access";
import type { TermsAcceptance, TermsAcceptances, TermsView } from "@/lib/access";
import { api } from "@/lib/api";
import { inline, mdBlocks, MORE, SHOWN_OPEN, splitVersions } from "@/lib/changelog";
import type { Version } from "@/lib/changelog";
import { errorMessageFrom } from "@/lib/licence";
import type { AboutView } from "@/lib/settings-console";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const date = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "");
const dateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "");

function Inline({ text }: { text: string }) {
  return (
    <>
      {inline(text).map((part, i) =>
        part.kind === "b" ? <strong key={i}>{part.text}</strong> : part.kind === "code" ? <code key={i}>{part.text}</code> : <Fragment key={i}>{part.text}</Fragment>,
      )}
    </>
  );
}

/** FTR's md(): headings, lists (one level in), bold and code only; the text is escaped by React. */
function Markdown({ text }: { text: string }) {
  return (
    <>
      {mdBlocks(text).map((block, i) => {
        if (block.kind === "ul")
          return (
            <ul key={i}>
              {block.items.map((item, j) => (
                <li key={j}>
                  <Inline text={item.text} />
                  {item.children.length ? (
                    <ul>
                      {item.children.map((child, k) => (
                        <li key={k}>
                          <Inline text={child.text} />
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
            </ul>
          );
        if (block.kind === "h") {
          const Heading = `h${Math.min(block.level, 4)}` as "h2" | "h3" | "h4";
          return (
            <Heading key={i}>
              <Inline text={block.text} />
            </Heading>
          );
        }
        return (
          <p key={i}>
            <Inline text={block.text} />
          </p>
        );
      })}
    </>
  );
}

function save(blob: Blob, name: string) {
  const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

/**
 * The accepted licence agreement (apps/api/app/services/terms_copy_service.py): who accepted which version for which
 * company, the SHA-256 of the text, and where its emailed copy is ("copy emailed on …", or "will be emailed when the
 * mail server is set up"). Owners and admins see every administrator's acceptance and can send a copy again; anyone
 * can download their own accepted copy. Acceptances are permanent: there is nothing to change or delete.
 */
function AcceptedAgreement({ canManage }: { canManage: boolean }) {
  const [data, setData] = useState<TermsAcceptances | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState("");

  const load = () =>
    api
      .getTermsAcceptances()
      .then(setData)
      .catch((error) => setStatus(message(error)));

  useEffect(() => {
    void load();
  }, []);

  async function resend(row: TermsAcceptance) {
    setBusy(row.id);
    setStatus("");
    try {
      const after = await api.resendTermsCopy(row.id);
      setStatus(after.copy.state === "waiting" ? `Queued: ${termsCopyStatus(after.copy, dateTime)}` : `A copy is on its way to ${after.copy.to}.`);
      window.setTimeout(() => void load(), 1500);
    } catch (error) {
      setStatus(message(error));
    } finally {
      setBusy("");
    }
  }

  async function download(row: TermsAcceptance, format: "html" | "txt") {
    try {
      save(await api.downloadTermsCopy(row.id, format), `hawk-ai-licence-agreement-v${row.version}${format === "html" ? "-accepted.html" : ".txt"}`);
    } catch (error) {
      setStatus(message(error));
    }
  }

  const rows = data?.acceptances ?? [];
  return (
    <div className="panel mt" data-ui="terms-acceptances">
      <h2>
        Accepted licence agreement <small>{canManage ? "every administrator's acceptance, newest first" : "your acceptance"}</small>
      </h2>
      {!data && !status ? <p className="muted">Loading…</p> : null}
      {data && !rows.length ? <p className="muted">Nothing accepted yet.</p> : null}
      {rows.map((row) => (
        <div key={row.id} className="terms-acceptance">
          <dl className="about-facts">
            <div>
              <dt>Accepted</dt>
              <dd>
                {row.scope === "organisation" ? "Licence agreement" : "Terms of use"} version {row.version}, {dateTime(row.acceptedAt)}
                {row.version !== data?.current.version ? <span className="muted"> (an earlier version)</span> : null}
              </dd>
            </div>
            {row.scope === "organisation" ? (
              <div>
                <dt>For</dt>
                <dd>
                  {row.companyName || "—"}, by {row.fullName || row.email} ({row.email}){row.via === "ACCEPT_TERMS" ? " through ACCEPT_TERMS" : ""}
                </dd>
              </div>
            ) : null}
            <div>
              <dt>SHA-256</dt>
              <dd className="mono small" style={{ wordBreak: "break-all" }}>
                {row.hash}
              </dd>
            </div>
            {row.scope === "organisation" ? (
              <div>
                <dt>Emailed copy</dt>
                <dd data-ui="terms-copy-status">{termsCopyStatus(row.copy, dateTime)}</dd>
              </div>
            ) : null}
          </dl>
          <div className="flex">
            <button type="button" className="sm" onClick={() => void download(row, "html")}>
              Download the accepted copy
            </button>
            <button type="button" className="sm ghost" onClick={() => void download(row, "txt")}>
              Exact text (.txt)
            </button>
            {canManage && row.scope === "organisation" ? (
              <button type="button" className="sm" disabled={busy === row.id} onClick={() => void resend(row)}>
                Email the copy again
              </button>
            ) : null}
          </div>
        </div>
      ))}
      <p role="status" aria-live="polite" className="small muted">
        {status}
      </p>
    </div>
  );
}

function VersionEntry({ version, open }: { version: Version; open: boolean }) {
  return (
    <details open={open}>
      <summary>{version.title}</summary>
      <div className="md">
        <Markdown text={version.body} />
      </div>
    </details>
  );
}

/**
 * Settings → About, laid out and worded as FTR Command Center's (public/js/about.js `aboutHtml()`): one panel of
 * facts — the version (HK-xx.xx.xx, from VERSION), the licence (the activation), the terms of use and the organisation —
 * the on-premise note and the terms card, then every version from CHANGELOG.md (the latest three open, earlier ones ten
 * at a time), and the third-party notices when this build carries them. For everyone signed in.
 */
export default function AboutSettingsPage() {
  const [view, setView] = useState<AboutView | null>(null);
  const [terms, setTerms] = useState<TermsView | null>(null);
  const [shown, setShown] = useState(SHOWN_OPEN);
  const [loadError, setLoadError] = useState("");
  const termsDialog = useRef<HTMLDialogElement>(null);
  const noticesDialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    api
      .getAbout()
      .then(setView)
      .catch((error) => setLoadError(message(error)));
    api
      .getTerms()
      .then(setTerms)
      .catch(() => undefined);
  }, []);

  const versions = view ? splitVersions(view.changelog) : [];
  const earlier = versions.length - shown;
  const next = Math.min(MORE, Math.max(0, earlier));
  const licence = view?.licence;

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-about">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">About</h1>
            <span className="crumbs">for the whole of Hawk AI</span>
          </div>
        </div>
        <div id="tab">
          {loadError ? (
            <div className="panel">
              <div className="empty">
                <b>{loadError}</b>
              </div>
            </div>
          ) : null}
          {!view && !loadError ? <p className="muted">Loading…</p> : null}
          {view && licence ? (
            <>
              <div className="panel about">
                <h2>About {view.appName}</h2>
                <p className="muted">
                  Where an organisation finds the AI it uses — the systems, the people and agents, what they do — sets the policies that govern it, puts the controls in place and keeps the evidence that they work.
                </p>
                <dl className="about-facts">
                  <div>
                    <dt>Version</dt>
                    <dd>
                      {view.versionLabel} <span className="muted">({view.version})</span>
                      {view.canUpdate ? (
                        <>
                          {" "}
                          · <Link href="/settings/updates">Versions and updates</Link>
                        </>
                      ) : null}
                    </dd>
                  </div>
                  <div>
                    <dt>Licence</dt>
                    <dd>
                      Proprietary ·{" "}
                      {licence.active ? (licence.activation ? `activated for ${licence.activation.org}, until ${date(licence.until)}` : `works until ${date(licence.until)} without an activation code`) : licence.message || "deactivated"}
                    </dd>
                  </div>
                  <div>
                    <dt>Terms accepted</dt>
                    <dd>{view.terms.accepted ? `Version ${view.terms.version}${view.terms.at ? `, ${dateTime(view.terms.at)}` : ""}` : "Not yet"}</dd>
                  </div>
                  <div>
                    <dt>Organisation</dt>
                    <dd>{view.organisationName}</dd>
                  </div>
                </dl>
                <p className="onprem-note">
                  <b>On premise, your data stays yours.</b> {terms?.notice ?? ""}
                </p>
                <div className="terms-card">
                  <h3>Licence agreement &amp; terms of use</h3>
                  <p className="muted small">
                    The End User Licence Agreement every owner or admin accepts for the organisation, and the terms of use every other person accepts, before using {view.appName}: version {view.terms.version}
                    {terms?.licensor ? `, licensed by ${terms.licensor}` : ""}. The activation codes that keep it working are under Settings → Activation codes.
                  </p>
                  <div className="flex">
                    <button type="button" className="primary" onClick={() => termsDialog.current?.showModal()} disabled={!terms}>
                      Read the licence agreement &amp; terms of use
                    </button>
                    {view.notices ? (
                      <button type="button" onClick={() => noticesDialog.current?.showModal()}>
                        Read the third-party notices
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
              {view.terms.accepted ? <AcceptedAgreement canManage={Boolean(view.terms.canManage)} /> : null}
              <div className="panel mt">
                <h2>
                  What is new <small>the latest three versions; earlier ones ten at a time</small>
                </h2>
                <div className="versions-log">
                  {versions.slice(0, shown).map((v, i) => (
                    <VersionEntry key={`${v.title}-${i}`} version={v} open={i < SHOWN_OPEN} />
                  ))}
                  {earlier > 0 ? (
                    <button type="button" className="sm" onClick={() => setShown((n) => n + MORE)}>
                      Show {next} earlier version{next === 1 ? "" : "s"} <span className="muted">· {earlier} more</span>
                    </button>
                  ) : null}
                </div>
              </div>
              <dialog ref={termsDialog} className="docd" aria-label="Licence agreement and terms of use">
                <div className="doc-head">
                  <b>Licence agreement &amp; terms of use</b>
                  <button type="button" className="sm ghost" onClick={() => termsDialog.current?.close()}>
                    Close
                  </button>
                </div>
                <div className="doc-text md">{terms ? <Markdown text={terms.text} /> : null}</div>
                <div className="doc-foot small muted">
                  Version {terms?.version} · SHA-256 {terms?.hash}
                </div>
              </dialog>
              {view.notices ? (
                <dialog ref={noticesDialog} className="docd" aria-label="Third-party notices">
                  <div className="doc-head">
                    <b>Third-party notices</b>
                    <button type="button" className="sm ghost" onClick={() => noticesDialog.current?.close()}>
                      Close
                    </button>
                  </div>
                  <div className="doc-text">
                    <pre>{view.notices.text}</pre>
                  </div>
                  <div className="doc-foot small muted">{view.notices.name}</div>
                </dialog>
              ) : null}
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
