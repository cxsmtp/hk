"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import { ALGORITHM_LABELS, AUDIT_GROUPS, auditBase, auditDetails, auditGroups, auditLabel, auditRefused, FILTER_KEYS, queryString, shortFingerprint, signatureFile, verifyVerdict } from "@/lib/records";
import type { AuditEvent, AuditPage, AuditVerify, EvidenceSigning } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const dateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");

type Filters = Record<(typeof FILTER_KEYS)[number], string>;
const EMPTY: Filters = { q: "", who: "", what: "", from: "", to: "", outcome: "" };

function Icon({ name }: { name: "search" | "download" }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      {name === "search" ? <path d="m21 21-4.3-4.3M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14Z" /> : <path d="M12 3v12m0 0-4-4m4 4 4-4M5 21h14" />}
    </svg>
  );
}

function save(blob: Blob, name: string) {
  const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
}

function Row({ e }: { e: AuditEvent }) {
  const refused = auditRefused(e);
  return (
    <tr className={refused ? "refused" : undefined}>
      <td className="small nowrap">{dateTime(e.at)}</td>
      <td>
        {e.actor?.name ?? "System"}
        <span className="sub">{e.actor?.email ?? ""}</span>
      </td>
      <td>
        <span className={`chip ${refused ? "bad" : /fail|broken/.test(e.action) ? "warn" : ""}`}>
          <i />
          {auditLabel(e.action)}
        </span>
        <span className="sub mono">{auditBase(e.action)}</span>
      </td>
      <td>{e.target}</td>
      <td className="small">
        {auditDetails(e.details).map(([k, v]) => (
          <span className="kvp" key={k}>
            <i>{k}</i> {v}{" "}
          </span>
        ))}
      </td>
      <td className="small mono">{e.ip}</td>
    </tr>
  );
}

/**
 * Evidence signing (app/api/routers/evidence_signing.py): what signs the evidence Hawk AI hands to auditors (the
 * exports here, the auditor's export), its fingerprint, and the keys it signed with before. Owners and admins rotate it.
 */
function EvidenceSigningPanel() {
  const [s, setS] = useState<EvidenceSigning | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getEvidenceSigning()
      .then(setS)
      .catch(() => setS(null));
  }, []);

  async function rotate() {
    if (!window.confirm("Make a new evidence signing key? Evidence signed before stays verifiable: the old public key stays published.")) return;
    setBusy(true);
    try {
      const out = await api.rotateEvidenceSigning();
      setS(out.status);
      toast.success(out.rotated ? "New signing key in use. The previous public key stays published." : "The key service still gives the same key: make a new key or version there first.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  if (!s) return null;
  return (
    <div className="panel mt" id="evidence-signing">
      <h2>
        Evidence signing <small>{s.backend_label || "Not set up"}</small>
      </h2>
      <p className="muted small">
        Exports and the auditor&apos;s evidence carry a signature an auditor checks offline with the public key alone (tools/verify_evidence.py). Public keys, current and retired:{" "}
        <a className="mono" href={s.well_known_path} target="_blank" rel="noreferrer">
          {s.well_known_path}
        </a>
      </p>
      {s.error ? <div className="callout bad">{s.error}</div> : null}
      {s.active ? (
        <dl className="kv">
          <dt>Key id (fingerprint)</dt>
          <dd className="mono" title={s.active.kid}>
            {shortFingerprint(s.active.kid)}
          </dd>
          <dt>Algorithm</dt>
          <dd>{ALGORITHM_LABELS[s.active.alg] ?? s.active.alg}</dd>
          {s.key_ref ? (
            <>
              <dt>Key</dt>
              <dd className="mono">{s.active.key_name || s.key_ref}</dd>
            </>
          ) : null}
          <dt>In use since</dt>
          <dd>{dateTime(s.active.created_at)}</dd>
          <dt>Retired keys</dt>
          <dd>{s.retired.length ? `${s.retired.length}, still published` : "None"}</dd>
        </dl>
      ) : null}
      {s.can_rotate ? (
        <div className="flex mt">
          <button className="btn ghost" id="evidence-rotate" type="button" disabled={busy} onClick={rotate}>
            Rotate the signing key
          </button>
        </div>
      ) : null}
    </div>
  );
}

/**
 * Records → Audit log, laid out and worded as FTR Command Center's Audit log (public/js/audit.js): every action, newest
 * first, the filters, "Check the log is intact" and the CSV export. Behind it, CxMissionZero's tamper-evident chain
 * (src/audit-log.js): the check names every broken entry, and the JSON Lines export carries each entry's MAC.
 */
export default function AuditLogPage() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [page, setPage] = useState<AuditPage | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [more, setMore] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [verified, setVerified] = useState<AuditVerify | null>(null);
  const [busy, setBusy] = useState(false);
  const qs = useMemo(() => queryString(applied), [applied]);

  const load = useCallback(async () => {
    try {
      const first = await api.getAuditLog(qs);
      setPage(first);
      setEvents(first.events);
      setMore(first.more);
      setLoadError("");
    } catch (error) {
      setLoadError(message(error));
    }
  }, [qs]);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  function apply(event: FormEvent) {
    event.preventDefault();
    setApplied({ ...filters });
  }

  async function older() {
    setBusy(true);
    try {
      const next = await api.getAuditLog(queryString({ ...applied, before: events.at(-1)?.at ?? "" }));
      setEvents((list) => [...list, ...next.events]);
      setMore(next.more);
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  async function verify() {
    setBusy(true);
    try {
      setVerified(await api.verifyAuditLog());
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  async function exportAs(format: "csv" | "jsonl") {
    try {
      const { blob, signature } = await api.exportAuditLogSigned(format, qs);
      save(blob, `audit.${format}`);
      // Its detached signature beside it, for an auditor to check offline (tools/verify_evidence.py, --signature).
      const sig = signatureFile(signature);
      if (sig) save(new Blob([sig], { type: "application/json" }), `audit.${format}.sig.json`);
    } catch (error) {
      toast.error(message(error));
    }
  }

  const groups = auditGroups(page?.actions ?? []);
  const verdict = verified ? verifyVerdict(verified, dateTime) : null;
  const set = (key: keyof Filters) => (event: { target: { value: string } }) => setFilters((f) => ({ ...f, [key]: event.target.value }));

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-audit">
        <div className="head">
          <div>
            <h1 className="serif">Audit log</h1>
            <p>
              Every action, by everyone: sign-ins, changes to people, connectors, policies and settings, exports and downloads, backups and support requests, and anything refused, with the reason. Newest first. Each entry is chained to the one before, so a changed or removed entry is found.
            </p>
          </div>
          <div className="flex">
            <button className="ghost" id="averify" type="button" disabled={busy} onClick={verify}>
              Check the log is intact
            </button>
            <button className="btn" id="aexport" type="button" onClick={() => exportAs("csv")}>
              <Icon name="download" />
              Export CSV
            </button>
            <button className="btn ghost" id="aexport-jsonl" type="button" title="Every entry with its MAC, for a SIEM" onClick={() => exportAs("jsonl")}>
              <Icon name="download" />
              Export JSON Lines
            </button>
          </div>
        </div>
        {loadError ? (
          <div className="panel">
            <div className="empty">
              <b>{loadError}</b>
            </div>
          </div>
        ) : null}
        {!page && !loadError ? <p className="muted">Loading…</p> : null}
        {page ? (
          <div className="panel">
            <form className="filters" id="af" onSubmit={apply}>
              <div className="search">
                <Icon name="search" />
                <input name="q" value={filters.q} onChange={set("q")} placeholder="Search everything" />
              </div>
              <label className="f">
                Who
                <select name="who" value={filters.who} onChange={set("who")}>
                  <option value="">Everyone</option>
                  {page.people.map((p) => (
                    <option key={p.email} value={p.email}>
                      {p.name} · {p.email}
                    </option>
                  ))}
                </select>
              </label>
              <label className="f">
                What
                <select name="what" value={filters.what} onChange={set("what")}>
                  <option value="">Every action</option>
                  {groups.map((g) => (
                    <optgroup key={g} label={AUDIT_GROUPS[g] ?? g}>
                      <option value={g}>All: {AUDIT_GROUPS[g] ?? g}</option>
                      {page.actions
                        .filter((a) => a.split(".")[0] === g)
                        .map((a) => (
                          <option key={a} value={a}>
                            {auditLabel(a)}
                          </option>
                        ))}
                    </optgroup>
                  ))}
                </select>
              </label>
              <label className="f">
                From
                <input type="date" name="from" value={filters.from} onChange={set("from")} />
              </label>
              <label className="f">
                To
                <input type="date" name="to" value={filters.to} onChange={set("to")} />
              </label>
              <label className="f">
                Outcome
                <select name="outcome" value={filters.outcome} onChange={set("outcome")}>
                  <option value="">All</option>
                  <option value="done">Done</option>
                  <option value="refused">Refused</option>
                </select>
              </label>
              <div className="flex">
                <button className="primary" type="submit">
                  Apply
                </button>
                {qs ? (
                  <button
                    className="btn ghost"
                    type="button"
                    onClick={() => {
                      setFilters(EMPTY);
                      setApplied(EMPTY);
                    }}
                  >
                    Clear
                  </button>
                ) : null}
              </div>
            </form>
            <div id="averified">
              {verdict && verified ? (
                verdict.ok ? (
                  <div className="callout ok mt">{verdict.text}</div>
                ) : (
                  <div className="callout bad mt">
                    <b>{verdict.title}</b>
                    {verdict.text}
                    <ul className="small">
                      {verified.problems.map((p, i) => (
                        <li key={`${p.seq}-${i}`}>
                          Entry {p.seq ?? "?"}
                          {p.at ? ` (${dateTime(p.at)})` : ""}: {p.problem}
                        </li>
                      ))}
                    </ul>
                  </div>
                )
              ) : null}
            </div>
            <div className="tw mt">
              <table className="audit">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Who</th>
                    <th>What</th>
                    <th>On</th>
                    <th>Details</th>
                    <th>Address</th>
                  </tr>
                </thead>
                <tbody id="arows">
                  {events.length ? (
                    events.map((e) => <Row key={e.id} e={e} />)
                  ) : (
                    <tr>
                      <td colSpan={6}>
                        <div className="empty">
                          <b>No events</b>Nothing matches these filters.
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="flex mt">
              <button id="amore" type="button" hidden={!more} disabled={busy} onClick={older}>
                Older entries
              </button>
              <span className="muted small" id="acount">
                {events.length} shown
              </span>
            </div>
          </div>
        ) : null}
        <EvidenceSigningPanel />
      </div>
    </AppShell>
  );
}
