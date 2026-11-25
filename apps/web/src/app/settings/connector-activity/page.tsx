"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import { CALL_OUTCOMES, queryString } from "@/lib/records";
import type { ConnectorActivity, ConnectorCall } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const dateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
const num = (n: number | null | undefined) => (n ?? 0).toLocaleString("en");

type Filters = { connector: string[]; host: string[]; outcome: string; from: string; to: string };
const EMPTY: Filters = { connector: [], host: [], outcome: "", from: "", to: "" };

/** FTR's multiPick (public/js/widgets.js): a list to tick several in, under a label. */
function MultiPick({ name, label, options, value, onChange }: { name: string; label: string; options: string[]; value: string[]; onChange: (next: string[]) => void }) {
  const ref = useRef<HTMLDetailsElement>(null);
  const shown = value.length === 0 ? "All" : value.length === 1 ? value[0] : `${value.length} chosen`;
  const toggle = (option: string) => onChange(value.includes(option) ? value.filter((v) => v !== option) : [...value, option]);
  return (
    <details className={`mpick${value.length ? " active" : ""}`} ref={ref} data-name={name}>
      <summary>
        {label}
        <span className="mp-v">{shown}</span>
      </summary>
      <div className="mp-menu">
        <div className="mp-acts">
          <button type="button" className="link" onClick={() => onChange([...options])}>
            All
          </button>
          <button type="button" className="link" onClick={() => onChange([])}>
            None
          </button>
        </div>
        <div className="mp-list">
          {options.map((option) => (
            <label key={option}>
              <input type="checkbox" checked={value.includes(option)} onChange={() => toggle(option)} />
              {option}
            </label>
          ))}
          {options.length ? null : <span className="muted small">Nothing yet</span>}
        </div>
      </div>
    </details>
  );
}

function Row({ e }: { e: ConnectorCall }) {
  return (
    <tr className={e.ok === false ? "refused" : undefined}>
      <td className="small nowrap">{dateTime(e.at)}</td>
      <td>{e.connector || "—"}</td>
      <td>
        <span className={`chip ${e.ok === false ? "bad" : ""}`}>
          <i />
          API call
        </span>
      </td>
      <td className="mono small">{e.host}</td>
      <td className="mono small">
        {e.method} {e.path}
      </td>
      <td className="small nowrap">
        {e.status ? (
          <>
            <b>{e.status}</b> ·{" "}
          </>
        ) : null}
        {e.ms !== null && e.ms !== undefined ? `${num(e.ms)} ms` : ""}
        {e.detail ? <span className="sub">{e.detail}</span> : null}
      </td>
    </tr>
  );
}

/**
 * Records → Connector API activity, laid out and worded as FTR Command Center's CxOne API audit (public/js/activity.js):
 * the figures of the last 30 days, the filters, and every call, newest first, with its result and time. Here the calls
 * are the ones Hawk AI's connectors make to the services they read (app/services/connector_activity.py).
 */
export default function ConnectorActivityPage() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [d, setD] = useState<ConnectorActivity | null>(null);
  const [events, setEvents] = useState<ConnectorCall[]>([]);
  const [more, setMore] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const qs = useMemo(() => queryString(filters), [filters]);

  const load = useCallback(async () => {
    try {
      const first = await api.getConnectorActivity(qs);
      setD(first);
      setEvents(first.events);
      setMore(first.more);
      setLoadError("");
    } catch (error) {
      setLoadError(message(error));
    }
  }, [qs]);

  useEffect(() => {
    // Filters apply as they change, as FTR's do.
    const timer = setTimeout(() => load().catch(() => undefined), 450);
    return () => clearTimeout(timer);
  }, [load]);

  async function older() {
    setBusy(true);
    try {
      const next = await api.getConnectorActivity(queryString({ ...filters, before: events.at(-1)?.at ?? "" }));
      setEvents((list) => [...list, ...next.events]);
      setMore(next.more);
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  async function exportCsv() {
    try {
      const blob = await api.exportConnectorActivity();
      const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "connector-activity.csv" });
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
    } catch (error) {
      toast.error(message(error));
    }
  }

  const sm = d?.summary;
  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-connector-activity">
        <div className="head">
          <div>
            <div className="crumbs">Records</div>
            <h1 className="serif">Connector API activity</h1>
            <p>Every call Hawk AI&apos;s connectors made to the services they read, for which connector, with its result and time. The path is shown without its query, and nothing of what was sent or received is kept. You see your own organisation&apos;s.</p>
          </div>
          <div className="flex">
            <button className="btn ghost" type="button" onClick={exportCsv}>
              Export CSV
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
        {!d && !loadError ? <p className="muted">Loading…</p> : null}
        {d && sm ? (
          <>
            <div className="kpis">
              <div className="kpi">
                <div className="k">API calls · 30 days</div>
                <div className="v">{num(sm.calls)}</div>
                <div className="s">{num(sm.avgMs)} ms on average</div>
              </div>
              <div className={`kpi ${sm.failed ? "warn" : ""}`}>
                <div className="k">Calls that did not succeed</div>
                <div className="v">{num(sm.failed)}</div>
                <div className="s">refused, failed or not answered</div>
              </div>
              <div className="kpi">
                <div className="k">Connectors</div>
                <div className="v">{num(sm.connectors)}</div>
                <div className="s">that made calls</div>
              </div>
              <div className="kpi">
                <div className="k">Services</div>
                <div className="v">{num(sm.hosts)}</div>
                <div className="s">hosts called</div>
              </div>
            </div>
            <div className="panel">
              <form className="filters" id="actf" onSubmit={(event) => event.preventDefault()}>
                <MultiPick name="connector" label="Connector" options={d.connectors} value={filters.connector} onChange={(connector) => setFilters((f) => ({ ...f, connector }))} />
                <MultiPick name="host" label="Service" options={d.hosts} value={filters.host} onChange={(host) => setFilters((f) => ({ ...f, host }))} />
                <label className="f">
                  Outcome
                  <select name="outcome" value={filters.outcome} onChange={(event) => setFilters((f) => ({ ...f, outcome: event.target.value }))}>
                    <option value="">All</option>
                    {CALL_OUTCOMES.map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="f">
                  From
                  <input type="date" name="from" value={filters.from} onChange={(event) => setFilters((f) => ({ ...f, from: event.target.value }))} />
                </label>
                <label className="f">
                  To
                  <input type="date" name="to" value={filters.to} onChange={(event) => setFilters((f) => ({ ...f, to: event.target.value }))} />
                </label>
                <div className="flex">
                  <button className="primary" type="button" onClick={() => load()}>
                    Apply
                  </button>
                  {qs ? (
                    <button className="btn ghost" type="button" onClick={() => setFilters(EMPTY)}>
                      Clear
                    </button>
                  ) : null}
                </div>
              </form>
              <div className="tw mt">
                <table className="audit">
                  <thead>
                    <tr>
                      <th>When</th>
                      <th>Connector</th>
                      <th>What</th>
                      <th>Service</th>
                      <th>Request</th>
                      <th>Result</th>
                    </tr>
                  </thead>
                  <tbody id="actrows">
                    {events.length ? (
                      events.map((e, i) => <Row key={`${e.at}-${i}`} e={e} />)
                    ) : (
                      <tr>
                        <td colSpan={6}>
                          <div className="empty">
                            <b>No activity yet</b>Calls the connectors make to the services they read show here.
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <div className="flex mt">
                <button id="actmore" type="button" hidden={!more} disabled={busy} onClick={older}>
                  Older entries
                </button>
                <span className="muted small" id="actcount">
                  {events.length} shown
                </span>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
