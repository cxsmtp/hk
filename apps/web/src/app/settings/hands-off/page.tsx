"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { SelfCheckBox } from "@/components/self-check-box";
import { DAYS, HOURS, handsOffPayload, readiness } from "@/lib/hands-off-settings";
import type { HandsOffView, SelfCheckHealth } from "@/lib/hands-off-settings";
import { errorMessageFrom } from "@/lib/licence";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");

type Form = { status: boolean; statusTo: string; statusDay: number; statusHour: number; replies: boolean; imapHost: string; imapPort: string };

const formFrom = (view: HandsOffView): Form => ({
  status: view.handsOff.statusTo.length > 0,
  statusTo: view.handsOff.statusTo.join("\n"),
  statusDay: view.handsOff.statusDay,
  statusHour: view.handsOff.statusHour,
  replies: view.handsOff.replies,
  imapHost: view.handsOff.imapHost,
  imapPort: String(view.handsOff.imapPort),
});

/**
 * Settings → Hands-off: CxMissionZero's page (public/index.html #set-handsoff, docs/hands-off.md) in FTR Command
 * Center's settings look. Set it up once, then leave it: the weekly status, who gets it and when, the email buttons and
 * replies, and the self-check. MZ's developer reminders (its questions 2 and the reminder parts of 1, 3 and 4) are
 * Checkmarx domain and are not in Hawk AI. Owners and admins only.
 */
export default function HandsOffSettingsPage() {
  const [view, setView] = useState<HandsOffView | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [editing, setEditing] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [status, setStatus] = useState<{ text: string; bad: boolean }>({ text: "", bad: false });
  const [health, setHealth] = useState<SelfCheckHealth | null>(null);
  const [checking, setChecking] = useState(false);

  const load = useCallback(async (keepForm = false) => {
    try {
      const next = await api.getHandsOff();
      setView(next);
      setHealth(next.health);
      if (!keepForm) setForm(formFrom(next));
      setLoadError("");
    } catch (error) {
      setLoadError(message(error));
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  function change(patch: Partial<Form>) {
    setEditing(true);
    setForm((current) => (current ? { ...current, ...patch } : current));
  }

  async function save(on: boolean) {
    if (!form) return;
    if (on && form.status && !form.statusTo.trim()) return setStatus({ text: "Add who gets the weekly status, or untick it.", bad: true });
    if (!on && !window.confirm("Turn off hands-off? The weekly status stops and replies are no longer read. The self-check keeps running.")) return;
    setStatus({ text: "Saving…", bad: false });
    try {
      const next = await api.saveHandsOff(handsOffPayload(form, on));
      setView(next);
      setHealth(next.health);
      setForm(formFrom(next));
      setEditing(false);
      setStatus({ text: on ? "Hands-off is on. Hawk AI now runs on its own." : "Hands-off is off.", bad: false });
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    }
  }

  async function sendNow() {
    setStatus({ text: "Sending…", bad: false });
    try {
      const r = await api.sendHandsOffStatus();
      setStatus({ text: r.sent === 1 ? "The status went to 1 person." : `The status went to ${r.sent} people.`, bad: false });
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    }
  }

  async function checkNow() {
    setChecking(true);
    try {
      setHealth((await api.checkNow()).health);
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    } finally {
      setChecking(false);
    }
  }

  const h = view?.handsOff;

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-hands-off">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Hands-off</h1>
            <span className="crumbs">for the whole of Hawk AI · Owners and admins only</span>
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
          {view && h && form ? (
            <div className="grid g2">
              <div className="panel" id="set-handsoff">
                <h2>
                  Hands-off: set it up once, then leave it{" "}
                  {h.on ? (
                    <span className="chip ok">
                      <i />
                      On
                    </span>
                  ) : (
                    <span className="chip">
                      <i />
                      Off
                    </span>
                  )}
                </h2>
                <p className="muted small">
                  Answer three questions and Hawk AI runs on its own: it emails a short status each week, takes requests from that email, and looks after itself. Nobody has to sign in again.
                </p>
                <ul className="small" id="ho-ready">
                  {readiness(view).map((line) => (
                    <li key={line.text} className={line.ok ? "ok-t" : "warn-t"}>
                      {line.ok ? "✓" : "!"} {line.text}
                    </li>
                  ))}
                </ul>

                <form className="form" onSubmit={(event) => event.preventDefault()} data-editing={editing ? "1" : ""}>
                  <h3>1 · What should Hawk AI do on its own?</h3>
                  <label className="check">
                    <input type="checkbox" id="ho-status" checked={form.status} onChange={(event) => change({ status: event.target.checked })} />
                    <span>Email a short status every week</span>
                  </label>
                  <p className="muted small">It also checks itself every few minutes, puts right what it can, and tells the administrators.</p>

                  <h3>2 · Who?</h3>
                  <label className="f">
                    The weekly status goes to
                    <textarea id="ho-status-to" rows={2} spellCheck={false} placeholder="security-lead@company.com" disabled={!form.status} value={form.statusTo} onChange={(event) => change({ statusTo: event.target.value })} />
                  </label>

                  <h3>3 · When?</h3>
                  <div className="row">
                    <label className="f">
                      The weekly status, on
                      <select id="ho-day" aria-label="Day of the week" value={form.statusDay} onChange={(event) => change({ statusDay: Number(event.target.value) })}>
                        {DAYS.map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="f">
                      at <span className="muted">the server&apos;s time</span>
                      <select id="ho-hour" aria-label="Hour" value={form.statusHour} onChange={(event) => change({ statusHour: Number(event.target.value) })}>
                        {HOURS.map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>

                  <h3>Steer it by email</h3>
                  <p className="muted small">Every status email has buttons: run the checks now, pause for a week, resume, stop the status. Each asks once more before it acts.</p>
                  <label className="check">
                    <input type="checkbox" id="ho-replies" checked={form.replies} onChange={(event) => change({ replies: event.target.checked })} />
                    <span>Also read replies: one word, such as PAUSE, RESUME, RUN, STATUS or STOP</span>
                  </label>
                  {form.replies ? (
                    <>
                      <div className="row" id="ho-imap">
                        <label className="f">
                          Mailbox server (IMAP), for the email server&apos;s account
                          <input id="ho-imap-host" spellCheck={false} placeholder="the email server's host" value={form.imapHost} onChange={(event) => change({ imapHost: event.target.value })} />
                        </label>
                        <label className="f">
                          Port
                          <input id="ho-imap-port" type="number" min={1} max={65535} value={form.imapPort} onChange={(event) => change({ imapPort: event.target.value })} />
                        </label>
                      </div>
                      <p className="muted small" id="ho-imap-hint">
                        Replies to Hawk AI&apos;s emails arrive in the mailbox it sends from. It reads only unread mail there, acts only on a reply from the address the email went to, and marks it read.
                      </p>
                    </>
                  ) : null}

                  <div className="flex">
                    <button type="button" className="primary" id="ho-save" onClick={() => save(true)}>
                      {h.on ? "Save" : "Turn on hands-off"}
                    </button>
                    <button type="button" className="ghost" id="ho-send" onClick={sendNow}>
                      Send the status now
                    </button>
                    {h.on ? (
                      <button type="button" className="ghost danger" id="ho-off" onClick={() => save(false)}>
                        Turn off hands-off
                      </button>
                    ) : null}
                    <span className={status.bad ? "err" : "small muted"} id="ho-status-line" role="status">
                      {status.text}
                    </span>
                  </div>
                </form>
                <h3 className="mt">Replies it understands</h3>
                <div className="tw">
                  <table>
                    <tbody>
                      {Object.entries(view.commands).map(([word, what]) => (
                        <tr key={word}>
                          <td className="mono small">{word.toUpperCase()}</td>
                          <td className="small">{what}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="panel" id="ho-health">
                <h2>Self-check</h2>
                <SelfCheckBox health={health} onCheck={checkNow} busy={checking} />
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
