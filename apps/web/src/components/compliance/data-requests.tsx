"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import {
  dataRequestQuery,
  DSR_FILTERS,
  DSR_KIND_LABELS,
  DSR_LAW_LABELS,
  DSR_STATUS_CHIP,
  DSR_STATUS_LABELS,
  dueWords,
  eventWords,
  nextStatuses,
} from "@/lib/compliance";
import type { DataRequestDetail, DataRequestFilter, DataRequestKind, DataRequestLaw, DataRequestList, DataRequestStatus } from "@/lib/compliance";
import { errorMessageFrom } from "@/lib/licence";
import { signatureFile } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const KINDS = Object.keys(DSR_KIND_LABELS) as DataRequestKind[];
const LAWS = Object.keys(DSR_LAW_LABELS) as DataRequestLaw[];
const day = (value: string | null) => (value ? value.slice(0, 10) : "—");
const when = (value: string | null) => (value ? value.replace("T", " ").slice(0, 16) + " UTC" : "—");

function save(blob: Blob, name: string) {
  const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
}

const EMPTY_FORM = { kind: "access" as DataRequestKind, law: "dpdp" as DataRequestLaw, subjectEmail: "", subjectIdentifier: "", receivedAt: "", channel: "", notes: "" };

/** Record a request: its kind, the law, who it is about and when it was received (today when left empty). */
function NewRequest({ dueDays, onSaved, onCancel }: { dueDays: number; onSaved: (detail: DataRequestDetail) => void; onCancel: () => void }) {
  const [form, setForm] = useState(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const set = (key: keyof typeof EMPTY_FORM) => (event: { target: { value: string } }) => setForm((f) => ({ ...f, [key]: event.target.value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      onSaved(await api.createDataRequest(form));
      setForm(EMPTY_FORM);
      toast.success(`Recorded. It is due in ${dueDays} days from when it was received.`);
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  return (
    <form className="panel form mt" onSubmit={submit} data-ui="dsr-new">
      <h2>
        Record a request <small>due {dueDays} days after it was received</small>
      </h2>
      <div className="row">
        <label className="f">
          What they ask
          <select value={form.kind} onChange={set("kind")} data-ui="dsr-new-kind">
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {DSR_KIND_LABELS[k]}
              </option>
            ))}
          </select>
        </label>
        <label className="f">
          Under
          <select value={form.law} onChange={set("law")}>
            {LAWS.map((l) => (
              <option key={l} value={l}>
                {DSR_LAW_LABELS[l]}
              </option>
            ))}
          </select>
        </label>
        <label className="f">
          Received on
          <input type="date" value={form.receivedAt} onChange={set("receivedAt")} />
        </label>
      </div>
      <div className="row">
        <label className="f">
          Their email
          <input type="email" value={form.subjectEmail} maxLength={320} autoComplete="off" onChange={set("subjectEmail")} data-ui="dsr-new-email" />
        </label>
        <label className="f">
          Or another identifier (employee number, phone)
          <input value={form.subjectIdentifier} maxLength={200} autoComplete="off" onChange={set("subjectIdentifier")} />
        </label>
        <label className="f">
          How it came (email, letter, form)
          <input value={form.channel} maxLength={32} onChange={set("channel")} />
        </label>
      </div>
      <label className="f">
        Notes (what they asked, how you will check who they are)
        <textarea rows={3} value={form.notes} maxLength={4000} onChange={set("notes")} />
      </label>
      <div className="flex">
        <button className="btn primary" type="submit" disabled={busy || (!form.subjectEmail.trim() && !form.subjectIdentifier.trim())}>
          Record the request
        </button>
        <button className="btn ghost" type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** One request: its details, what can be done next, and its trail. */
function RequestDetail({ detail, onChanged, onClose }: { detail: DataRequestDetail; onChanged: (next: DataRequestDetail) => void; onClose: () => void }) {
  const { request, events, mayManage } = detail;
  const [note, setNote] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const due = dueWords(request);
  const next = mayManage ? nextStatuses(request.status) : [];

  async function act(work: () => Promise<DataRequestDetail>, done: string) {
    setBusy(true);
    try {
      onChanged(await work());
      setNote("");
      setReason("");
      toast.success(done);
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  function move(status: DataRequestStatus) {
    void act(() => api.updateDataRequest(request.id, { status, note, refusalReason: status === "refused" ? reason : undefined }), `${DSR_STATUS_LABELS[status]}.`);
  }

  async function download() {
    setBusy(true);
    try {
      const { blob, signature } = await api.exportDataRequest(request.id);
      save(blob, `hawk-data-request-${request.id.slice(0, 8)}-export.json`);
      const sig = signatureFile(signature);
      if (sig) save(new Blob([sig], { type: "application/json" }), `hawk-data-request-${request.id.slice(0, 8)}-export.json.sig.json`);
      onChanged(await api.getDataRequest(request.id));
      toast.success("Downloaded. Send it to the person, then complete the request.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  function erase() {
    if (!window.confirm("Erase this person's personal data in this workspace? Their account is switched off and their name, email and other personal fields are replaced by a pseudonym in every record. The audit log is kept as it is. This cannot be undone.")) return;
    void act(() => api.eraseDataRequest(request.id), "Erased by pseudonymisation; the request is completed.");
  }

  return (
    <div className="panel mt" data-ui="dsr-detail" data-request={request.id}>
      <h2>
        {DSR_KIND_LABELS[request.kind]}
        <span className={`chip ${DSR_STATUS_CHIP[request.status]}`}>
          <i />
          {DSR_STATUS_LABELS[request.status]}
        </span>
      </h2>
      <div className="grid g2">
        <dl className="kv">
          <dt>Person</dt>
          <dd>
            {request.subjectEmail || "—"}
            {request.subjectIdentifier ? ` · ${request.subjectIdentifier}` : ""}
            <span className="small muted"> {request.subjectMatched ? "(has an account here)" : "(no account here)"}</span>
          </dd>
          <dt>Under</dt>
          <dd>{DSR_LAW_LABELS[request.law]}</dd>
          <dt>Received</dt>
          <dd>
            {day(request.receivedAt)}
            {request.channel ? ` · ${request.channel}` : ""}
          </dd>
          <dt>Due</dt>
          <dd>
            <span className={due.chip ? `chip ${due.chip}` : ""}>{due.text}</span>
          </dd>
          <dt>Handled by</dt>
          <dd>{request.handledBy || "—"}</dd>
          {request.completedAt ? (
            <>
              <dt>Finished</dt>
              <dd>{when(request.completedAt)}</dd>
            </>
          ) : null}
          {request.refusalReason ? (
            <>
              <dt>Why refused</dt>
              <dd>{request.refusalReason}</dd>
            </>
          ) : null}
          <dt>Reference</dt>
          <dd className="mono small">{request.id}</dd>
        </dl>
        <div>
          <h3>Trail</h3>
          <ol className="timeline" data-ui="dsr-timeline">
            {events.map((e) => (
              <li key={e.id}>
                <b>{eventWords(e)}</b> <span className="muted small">{when(e.at)} · {e.by || "system"}</span>
                {e.note ? <span className="sub small">{e.note}</span> : null}
              </li>
            ))}
          </ol>
        </div>
      </div>
      {mayManage ? (
        <div className="form mt" data-ui="dsr-actions">
          <div className="flex">
            {request.kind === "access" && request.status !== "refused" ? (
              <button className="btn" type="button" disabled={busy} onClick={download} data-ui="dsr-export">
                Download what Hawk AI holds
              </button>
            ) : null}
            {request.kind === "erasure" && next.length ? (
              <button className="btn danger" type="button" disabled={busy} onClick={erase} data-ui="dsr-erase">
                Erase by pseudonymisation
              </button>
            ) : null}
            {next.length ? (
              <button className="btn ghost" type="button" disabled={busy} onClick={() => void act(() => api.updateDataRequest(request.id, { handledBy: "me" }), "It is yours.")}>
                I will handle it
              </button>
            ) : null}
          </div>
          {next.length ? (
            <>
              <label className="f">
                Note (what was done; kept in the trail)
                <textarea rows={2} value={note} maxLength={4000} onChange={(e) => setNote(e.target.value)} data-ui="dsr-note" />
              </label>
              <label className="f">
                Why it is refused (only when refusing; the person may complain to the regulator)
                <input value={reason} maxLength={4000} onChange={(e) => setReason(e.target.value)} />
              </label>
              <div className="flex" data-ui="dsr-status-actions">
                {next.map((s) => (
                  <button key={s} className={`btn${s === "completed" ? " primary" : ""}`} type="button" disabled={busy || (s === "refused" && !reason.trim())} onClick={() => move(s)}>
                    {s === "completed" ? "Complete" : s === "refused" ? "Refuse" : DSR_STATUS_LABELS[s]}
                  </button>
                ))}
                <button className="btn ghost" type="button" disabled={busy || !note.trim()} onClick={() => void act(() => api.updateDataRequest(request.id, { note }), "Note added.")}>
                  Add the note
                </button>
              </div>
            </>
          ) : null}
        </div>
      ) : (
        <p className="small muted">Those who answer data requests (owners, admins, or a role given it) move it on.</p>
      )}
      <div className="flex mt">
        <button className="btn ghost" type="button" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}

/**
 * Settings → Compliance → Data requests (apps/api/app/services/data_subject_requests.py): people's requests to see,
 * correct or erase their personal data, grievances and nominations (India's DPDP Act s.11-14, the UAE PDPL Art. 13-15),
 * each with its due date (30 days by default), status and trail; an access request is answered with an export of what
 * Hawk AI holds about the person, an erasure by pseudonymisation (the audit log is kept). Overdue requests show first.
 */
export function DataRequests() {
  const [list, setList] = useState<DataRequestList | null>(null);
  const [filter, setFilter] = useState<DataRequestFilter>("open");
  const [detail, setDetail] = useState<DataRequestDetail | null>(null);
  const [adding, setAdding] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [settingsForm, setSettingsForm] = useState({ dueDays: "", grievanceContact: "" });
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .listDataRequests(dataRequestQuery(filter))
      .then((next) => {
        setList(next);
        setLoadError("");
        setSettingsForm({ dueDays: String(next.settings.dueDays), grievanceContact: next.settings.grievanceContact });
      })
      .catch((error) => setLoadError(message(error)));
  }, [filter]);

  useEffect(load, [load]);

  function changed(next: DataRequestDetail) {
    setDetail(next);
    load();
  }

  async function open(id: string) {
    try {
      setDetail(await api.getDataRequest(id));
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    if (!list) return;
    const days = Number(settingsForm.dueDays);
    if (!Number.isInteger(days) || days < list.settings.minDueDays || days > list.settings.maxDueDays) {
      toast.error(`A request is due within ${list.settings.minDueDays} to ${list.settings.maxDueDays} days.`);
      return;
    }
    setBusy(true);
    try {
      await api.saveDataRequestSettings({ dueDays: days, grievanceContact: settingsForm.grievanceContact });
      load();
      toast.success("Saved. New requests use it; requests already recorded keep their due date.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  if (loadError && !list) {
    return (
      <div className="panel">
        <div className="empty">
          <b>{loadError}</b>
        </div>
      </div>
    );
  }
  if (!list) return <p className="muted">Loading the data requests…</p>;

  const { summary, settings } = list;
  return (
    <div data-ui="compliance-data-requests">
      <div className="kpis">
        <div className="kpi">
          <div className="k">Open</div>
          <div className="v">{summary.open}</div>
        </div>
        <div className="kpi">
          <div className="k">Overdue</div>
          <div className="v">{summary.overdue}</div>
        </div>
        <div className="kpi">
          <div className="k">Due within {summary.dueSoonDays} days</div>
          <div className="v">{summary.dueSoon}</div>
        </div>
        <div className="kpi">
          <div className="k">Completed</div>
          <div className="v">{summary.completed}</div>
        </div>
      </div>
      {summary.overdue ? (
        <div className="callout warn mt" data-ui="dsr-overdue">
          {summary.overdue} request{summary.overdue === 1 ? " is" : "s are"} past the due date. Answer {summary.overdue === 1 ? "it" : "them"}, or record why not: the DPDP and UAE PDPL packs show this as a gap until then.
        </div>
      ) : null}
      {!settings.grievanceContact ? (
        <div className="callout mt" data-ui="dsr-no-grievance-contact">
          Name your grievance contact below: the person who answers questions and complaints about personal data (DPDP s.8(9) and R.9).
        </div>
      ) : null}
      {adding && list.mayManage ? (
        <NewRequest
          dueDays={settings.dueDays}
          onCancel={() => setAdding(false)}
          onSaved={(next) => {
            setAdding(false);
            setFilter("open");
            changed(next);
          }}
        />
      ) : null}
      {detail ? <RequestDetail detail={detail} onChanged={changed} onClose={() => setDetail(null)} /> : null}
      <div className="panel mt">
        <h2>
          Requests <small>open ones soonest due first</small>
        </h2>
        <div className="flex">
          <div className="seg" aria-label="Which requests" data-ui="dsr-filter">
            {DSR_FILTERS.map((f) => (
              <button key={f.key} type="button" className={filter === f.key ? "primary" : ""} aria-pressed={filter === f.key} onClick={() => setFilter(f.key)}>
                {f.label}
              </button>
            ))}
          </div>
          {list.mayManage && !adding ? (
            <button className="btn" type="button" onClick={() => setAdding(true)} data-ui="dsr-add">
              Record a request
            </button>
          ) : null}
        </div>
        <div className="tw mt">
          <table data-ui="dsr-table">
            <thead>
              <tr>
                <th>Request</th>
                <th>Person</th>
                <th>Received</th>
                <th>Due</th>
                <th>Status</th>
                <th>Handled by</th>
                <th>
                  <span className="sr-only">Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((r) => {
                const due = dueWords(r);
                return (
                  <tr key={r.id} data-request={r.id}>
                    <td>
                      <b>{DSR_KIND_LABELS[r.kind]}</b>
                      <span className="sub">{DSR_LAW_LABELS[r.law]}</span>
                    </td>
                    <td className="small">
                      {r.subjectEmail || r.subjectIdentifier || "—"}
                      <span className="sub">{r.subjectMatched ? "Has an account here" : "No account here"}</span>
                    </td>
                    <td className="small nowrap">{day(r.receivedAt)}</td>
                    <td className="small">{due.chip ? <span className={`chip ${due.chip}`}>{due.text}</span> : due.text}</td>
                    <td className="nowrap">
                      <span className={`chip ${DSR_STATUS_CHIP[r.status]}`}>
                        <i />
                        {DSR_STATUS_LABELS[r.status]}
                      </span>
                    </td>
                    <td className="small">{r.handledBy || "—"}</td>
                    <td className="actions">
                      <button className="btn sm" type="button" onClick={() => void open(r.id)} data-ui="dsr-open">
                        Open
                      </button>
                    </td>
                  </tr>
                );
              })}
              {!list.items.length ? (
                <tr>
                  <td colSpan={7} className="muted">
                    {filter === "open" ? "No open requests." : "Nothing matches."}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
      <div className="grid g2 mt">
        <form className="panel form" onSubmit={saveSettings} data-ui="dsr-settings">
          <h2>Due date and grievance contact</h2>
          <p className="small muted">
            A request is due {settings.defaultDueDays} days after it was received unless you set otherwise ({settings.minDueDays}–{settings.maxDueDays}). Check the current rules of the law you answer under: the UAE PDPL&apos;s Executive Regulations and the DPDP Rules set the final periods.
          </p>
          <label className="f">
            Days to answer a request
            <input inputMode="numeric" value={settingsForm.dueDays} disabled={!list.mayManage} onChange={(e) => setSettingsForm((f) => ({ ...f, dueDays: e.target.value }))} />
          </label>
          <label className="f">
            Grievance contact (name, email, phone)
            <input value={settingsForm.grievanceContact} maxLength={320} disabled={!list.mayManage} onChange={(e) => setSettingsForm((f) => ({ ...f, grievanceContact: e.target.value }))} />
          </label>
          {list.mayManage ? (
            <button className="btn mt" type="submit" disabled={busy}>
              Save
            </button>
          ) : (
            <p className="small muted">Those who answer data requests change these.</p>
          )}
        </form>
        <div className="panel">
          <h2>How it works</h2>
          <ul className="small">
            <li>
              <b>See their data</b>: download what Hawk AI holds about the person in this workspace (account, role, audit entries they made, console activity, AI activity with masked prompts only, alerts, findings, devices, support cases), signed, and send it to them.
            </li>
            <li>
              <b>Erase their data</b>: their account is switched off and every personal field is replaced by a stable pseudonym. The audit log is never changed: its entries point at the pseudonymised account. The last active Owner cannot be erased.
            </li>
            <li>
              <b>Correct their data</b>, <b>grievances</b> and <b>nominations</b>: do what is asked (Settings → People for names and emails), then complete the request with a note.
            </li>
            <li>Every step is in the request&apos;s trail and in the audit log, and goes into the DPDP and UAE PDPL evidence bundles (without whom it is about).</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
