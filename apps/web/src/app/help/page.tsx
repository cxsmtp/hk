"use client";

import "../settings/ftr-settings.css";

import { Fragment, useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import { HELP_KIND, HELP_PRIORITY, HELP_STATUS, helpCrumbs, sentToast } from "@/lib/records";
import type { SupportKind, SupportList, SupportRequest, SupportStatus } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : "");

/** FTR's ago(): "3 min ago", "yesterday", or the date. */
function ago(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} h ago`;
  if (seconds < 172_800) return "yesterday";
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function StatusChip({ status }: { status: SupportStatus }) {
  const [label, tone] = HELP_STATUS[status] ?? [status, ""];
  return (
    <span className={`chip ${tone}`}>
      <i />
      {label}
    </span>
  );
}

/** One request, opened in place: its conversation, an answer, the status (the support team) and its history
 * (CxMissionZero's renderHelpRequest, in the classes FTR's Get help used for its conversation). */
function Detail({ r, team, onChanged }: { r: SupportRequest; team: boolean; onChanged: (r: SupportRequest) => void }) {
  const [text, setText] = useState("");
  const [status, setStatus] = useState<SupportStatus>(r.status);
  const [say, setSay] = useState("");

  async function answer(event: FormEvent) {
    event.preventDefault();
    setSay("Sending…");
    try {
      const done = await api.writeOnSupportRequest(r.id, text);
      setText("");
      setSay(done.emailed?.error ? `Kept, but the email did not go: ${done.emailed.error}` : "Sent.");
      onChanged(done.request);
    } catch (error) {
      setSay(message(error));
    }
  }

  async function move() {
    setSay("Updating…");
    try {
      const done = await api.setSupportStatus(r.id, status);
      setSay(done.emailed?.error ? `Updated, but the email did not go: ${done.emailed.error}` : "Updated.");
      onChanged(done.request);
    } catch (error) {
      setSay(message(error));
    }
  }

  return (
    <div>
      <div className="help-head">
        <span className="mono">{r.id}</span>
        <span className="chip">{HELP_KIND[r.kind]}</span>
        <StatusChip status={r.status} />
        {r.priority ? (
          <span className="muted small">
            Priority: {HELP_PRIORITY[r.priority] ?? r.priority}
          </span>
        ) : null}
      </div>
      <h2 className="help-subject">{r.subject}</h2>
      <p className="muted small">
        Raised by {r.requester.name || r.requester.email} · {when(r.createdAt)}
        {r.version ? ` · ${r.version}` : ""}
      </p>
      <ol className="help-thread">
        {(r.conversation ?? []).map((m, i) => (
          <li key={`${m.at}-${i}`} className={`help-msg${m.team ? " team" : ""}${m.mine ? " mine" : ""}`}>
            <div className="help-msg-head">
              <b>{m.name}</b>
              {m.team ? (
                <span className="chip ok">
                  <i />
                  Support team
                </span>
              ) : null}
              <span className="muted small">{when(m.at)}</span>
            </div>
            <div className="help-msg-text">{m.text}</div>
          </li>
        ))}
      </ol>
      <form className="form" onSubmit={answer}>
        <label className="f">
          {r.mine ? "Add to your request" : "Answer"}
          <textarea rows={4} maxLength={10000} required value={text} onChange={(event) => setText(event.target.value)} placeholder={r.mine ? "More detail, or an answer to the support team" : "Your answer: it is emailed to the person who raised it"} />
        </label>
        <div className="flex">
          <button type="submit" className="primary">
            Send
          </button>
          <span className="muted small" role="status">
            {say}
          </span>
        </div>
      </form>
      {team ? (
        <div className="help-set">
          <label className="f">
            Status
            <select value={status} onChange={(event) => setStatus(event.target.value as SupportStatus)}>
              {Object.entries(HELP_STATUS).map(([id, [label]]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <button type="button" onClick={move}>
            Update status
          </button>
          <p className="muted small">The person who raised it gets an email with the new status.</p>
        </div>
      ) : null}
      <details className="help-history">
        <summary>Status history</summary>
        <ul>
          {(r.history ?? []).map((h, i) => (
            <li key={`${h.at}-${i}`}>
              <StatusChip status={h.status} /> {h.name} · {when(h.at)}
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

/**
 * Get help, laid out and worded as FTR Command Center's (public/js/help.js): one form ("Something is not working" or
 * "I would like something added or changed"), then what was sent, newest first, each opened in place. Behind it,
 * CxMissionZero's support desk (src/support.js): numbers SUP-0001 and ENH-0001, statuses, a conversation, an email at
 * every step, and the support team's queue (the organisation's owners and admins). In email mode, Send opens the
 * person's own email app with the template instead.
 */
export default function GetHelpPage() {
  const [d, setD] = useState<SupportList | null>(null);
  const [loadError, setLoadError] = useState("");
  const [kind, setKind] = useState<SupportKind>("case");
  const [subject, setSubject] = useState("");
  const [text, setText] = useState("");
  const [priority, setPriority] = useState("normal");
  const [say, setSay] = useState("");
  const [sending, setSending] = useState(false);
  const [open, setOpen] = useState<SupportRequest | null>(null);
  const [onlyMine, setOnlyMine] = useState(false);

  const load = useCallback(async (openId?: string) => {
    try {
      const list = await api.getSupport();
      setD(list);
      setLoadError("");
      if (openId) setOpen((await api.getSupportRequest(openId)).request);
    } catch (error) {
      setLoadError(message(error));
    }
  }, []);

  useEffect(() => {
    const match = /^(SUP|ENH)-\d+$/i.exec(new URLSearchParams(window.location.search).get("open") ?? window.location.hash.replace(/^#/, ""));
    load(match ? match[0].toUpperCase() : undefined).catch(() => undefined);
  }, [load]);

  async function send(event: FormEvent) {
    event.preventDefault();
    setSending(true);
    setSay("Sending…");
    try {
      if (d?.channel.mode === "email") {
        const { href } = await api.supportMailto(kind);
        window.location.href = href;
        setSay("");
      } else {
        const r = await api.raiseSupportRequest({ kind, subject, text, priority, page: document.referrer ? "" : window.location.pathname });
        const said = sentToast(r);
        if (said.bad) toast.error(said.text);
        else toast.success(said.text);
        setSubject("");
        setText("");
        setSay("");
        await load(r.request.id);
      }
    } catch (error) {
      setSay(message(error));
    }
    setSending(false);
  }

  async function show(r: SupportRequest) {
    if (open?.id === r.id) return setOpen(null);
    try {
      setOpen((await api.getSupportRequest(r.id)).request);
    } catch (error) {
      toast.error(message(error));
    }
  }

  const changed = (r: SupportRequest) => {
    setOpen(r);
    load().catch(() => undefined);
  };
  const requests = (d?.requests ?? []).filter((r) => !onlyMine || r.mine);
  const cols = d?.team ? 6 : 5;

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="get-help">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Get help</h1>
            <span className="crumbs">{helpCrumbs(d?.channel)}</span>
          </div>
        </div>
        {loadError ? (
          <div className="panel">
            <div className="empty">
              <b>{loadError}</b>
            </div>
          </div>
        ) : null}
        {!d && !loadError ? <p className="muted">Loading…</p> : null}
        {d ? (
          <>
            <div className="panel help-form">
              <form id="hf" className="form" autoComplete="off" onSubmit={send}>
                <div className="seg" id="hkind" role="radiogroup" aria-label="What is it?">
                  <button type="button" role="radio" aria-checked={kind === "case"} className={kind === "case" ? "primary" : ""} onClick={() => setKind("case")}>
                    Something is not working
                  </button>
                  <button type="button" role="radio" aria-checked={kind === "enhancement"} className={kind === "enhancement" ? "primary" : ""} onClick={() => setKind("enhancement")}>
                    I would like something added or changed
                  </button>
                </div>
                {d.channel.mode === "email" ? (
                  <p className="muted small">Opens your email app, addressed to {d.channel.email}, with a short template to fill in.</p>
                ) : (
                  <>
                    <label className="f">
                      In a few words
                      <input name="subject" maxLength={200} required value={subject} onChange={(event) => setSubject(event.target.value)} placeholder={kind === "case" ? "The connector stops at the first page" : "A column for the renewal date"} />
                    </label>
                    <label className="f">
                      The details
                      <textarea name="text" rows={6} maxLength={10000} required value={text} onChange={(event) => setText(event.target.value)} placeholder="What happened, what you expected, and the steps to see it" />
                    </label>
                  </>
                )}
                <div className="flex">
                  {kind === "case" && d.channel.mode !== "email" ? (
                    <label className="f" id="hprio-l">
                      How urgent
                      <select name="priority" value={priority} onChange={(event) => setPriority(event.target.value)}>
                        <option value="low">Low</option>
                        <option value="normal">Normal</option>
                        <option value="high">High</option>
                        <option value="urgent">Urgent: I cannot work</option>
                      </select>
                    </label>
                  ) : null}
                  <span className="spacer" />
                  <span className="muted small" id="hsay" aria-live="polite">
                    {say}
                  </span>
                  <button className="primary" type="submit" disabled={sending}>
                    Send
                  </button>
                </div>
              </form>
            </div>
            <div className="panel mt">
              <h2>
                <span>
                  {d.team ? "Sent by everyone" : "What you sent"} <small>{requests.length ? "the latest first; click one to read it" : "nothing yet"}</small>
                </span>
                {d.team ? (
                  <label className="switch">
                    <input type="checkbox" checked={onlyMine} onChange={(event) => setOnlyMine(event.target.checked)} />
                    <span>Mine</span>
                  </label>
                ) : null}
              </h2>
              {requests.length ? (
                <div className="tw">
                  <table>
                    <thead>
                      <tr>
                        <th>Number</th>
                        <th>Type</th>
                        <th>In a few words</th>
                        <th>Status</th>
                        {d.team ? <th>From</th> : null}
                        <th>Sent</th>
                      </tr>
                    </thead>
                    <tbody id="hrows">
                      {requests.map((r) => (
                        <Fragment key={r.id}>
                          <tr className="click" data-id={r.id} onClick={() => show(r)}>
                            <td className="mono">{r.id}</td>
                            <td>{HELP_KIND[r.kind] ?? r.kind}</td>
                            <td>
                              <b>{r.subject}</b>
                            </td>
                            <td>
                              <StatusChip status={r.status} />
                            </td>
                            {d.team ? <td>{r.requester.name || r.requester.email}</td> : null}
                            <td data-sort={r.createdAt}>{ago(r.createdAt)}</td>
                          </tr>
                          {open?.id === r.id ? (
                            <tr className="help-detail">
                              <td colSpan={cols}>
                                <Detail key={`${open.id}-${open.updatedAt}`} r={open} team={d.team} onChanged={changed} />
                              </td>
                            </tr>
                          ) : null}
                        </Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty">Requests you send are listed here.</div>
              )}
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
