"use client";

import "../ftr-settings.css";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { DataRequests } from "@/components/compliance/data-requests";
import { FrameworkPacks } from "@/components/compliance/framework-packs";
import { api } from "@/lib/api";
import { clockSentence, incidentQuery, OWNER_LABELS, retentionDays, STATUS_CHIP, STATUS_LABELS } from "@/lib/compliance";
import type { ComplianceView, ControlStatus } from "@/lib/compliance";
import { errorMessageFrom } from "@/lib/licence";
import { signatureFile } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const ORDER: ControlStatus[] = ["action", "partial", "customer", "met"];

function save(blob: Blob, name: string) {
  const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
}

/**
 * Settings → Compliance (/settings/guide/compliance), for owners, admins and auditors: each control of Dubai's
 * Information Security Regulation (DESC ISR v3), the UAE IA Standard and India's CERT-In directions that Hawk AI takes
 * part in, with its status now and a link to where it is set or shown; the clock and encryption at rest; how long
 * activity is kept, the data location and the incident contact (owners and admins change them); and the incident
 * report for a time window. The organisation's own processes (an ISMS, risk assessment, HR security, suppliers, the
 * incident response plan, business continuity) are not software: the page says so.
 *
 * The first tab is the framework packs (components/compliance/framework-packs.tsx): one per law or standard, each
 * requirement with the Hawk AI controls behind it, their live status, records of the organisation's own processes and
 * the signed evidence bundle. The third is the data requests (components/compliance/data-requests.tsx): people's
 * requests to see, correct or erase their personal data, grievances and nominations (DPDP, UAE PDPL), each with its due
 * date and trail; overdue and due-soon requests are called out above every tab.
 */
export default function CompliancePage() {
  const [view, setView] = useState<ComplianceView | null>(null);
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ activity: "", connector: "", location: "", contact: "" });
  const [windowFrom, setWindowFrom] = useState("");
  const [windowTo, setWindowTo] = useState("");
  const [tab, setTab] = useState<"packs" | "desc" | "requests">("packs");

  const show = useCallback((next: ComplianceView) => {
    setView(next);
    setForm({
      activity: String(next.settings.activityRetentionDays),
      connector: String(next.settings.connectorRetentionDays),
      location: next.settings.dataLocation,
      contact: next.settings.incidentContact,
    });
  }, []);

  useEffect(() => {
    // A link may open a tab (/settings/compliance?tab=requests): read once, in the browser.
    const wanted = new URLSearchParams(window.location.search).get("tab");
    if (wanted === "requests" || wanted === "desc") setTab(wanted);
    api
      .getCompliance()
      .then(show)
      .catch((error) => {
        setLoadError(message(error));
        // Someone who answers data requests without seeing the audit log has only that tab.
        setTab("requests");
      });
  }, [show]);

  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    if (!view) return;
    const { minRetentionDays: min, maxRetentionDays: max } = view.settings;
    const activity = retentionDays(form.activity, min, max);
    const connector = retentionDays(form.connector, min, max);
    if (activity === null || connector === null) {
      toast.error(`Keep activity between ${min} and ${max} days.`);
      return;
    }
    setBusy(true);
    try {
      show(await api.saveCompliance({ activityRetentionDays: activity, connectorRetentionDays: connector, dataLocation: form.location, incidentContact: form.contact }));
      toast.success("Saved.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  async function baseline() {
    if (!view) return;
    if (!window.confirm("Apply the recommended sign-in baseline? Passwords: 12 characters, 3 kinds of character, not one of the last 5, changed every 90 days; signed out after 15 minutes without activity. Anyone whose password is older than 90 days chooses a new one at their next sign-in.")) return;
    setBusy(true);
    try {
      await api.saveSignInSettings({ passwordRule: { minLength: 12, classes: 3, history: 5, maxAgeDays: 90 }, sessionIdleMinutes: 15 });
      show(await api.getCompliance());
      toast.success("The recommended baseline is in force. Write the sign-in notice and require two-step sign-in under Settings → Sign-in.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  async function report() {
    setBusy(true);
    try {
      const { blob, signature } = await api.incidentReport(incidentQuery(windowFrom, windowTo));
      save(blob, "hawk-incident-report.json");
      const sig = signatureFile(signature);
      if (sig) save(new Blob([sig], { type: "application/json" }), "hawk-incident-report.json.sig.json");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  const controls = view ? [...view.controls].sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status)) : [];

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-compliance">
        <div className="head">
          <div>
            <h1 className="serif">Compliance</h1>
            <p>
              Framework packs for the laws and standards you work to (India&apos;s DPDP, the UAE PDPL, DESC ISR, ISO 27001 and 42001, PCI DSS, CIS, NIST, Saudi NCA and SAMA, Australia&apos;s, OWASP, MITRE ATLAS and the EU AI Act): each requirement, the Hawk AI controls behind it, their status now worked out from the settings in force, and signed evidence. The DESC / UAE IA / CERT-In view keeps the clock, retention, residency and the incident report. Packs support compliance: they do not by themselves make you compliant or certified. See <Link href="/settings/guide/compliance">Guide → Compliance</Link>.
            </p>
          </div>
          {view?.mayChange && tab === "desc" ? (
            <div className="flex">
              <button className="btn" type="button" disabled={busy} onClick={baseline} data-ui="compliance-baseline">
                Apply the recommended baseline
              </button>
            </div>
          ) : null}
        </div>
        {view?.dataRequests && (view.dataRequests.overdue || view.dataRequests.dueSoon) && tab !== "requests" ? (
          <div className="callout warn" data-ui="compliance-dsr-due">
            Data requests: {view.dataRequests.overdue} overdue, {view.dataRequests.dueSoon} due within {view.dataRequests.dueSoonDays} days.{" "}
            <button className="btn sm" type="button" onClick={() => setTab("requests")}>
              Open data requests
            </button>
          </div>
        ) : null}
        {loadError && tab !== "requests" ? (
          <div className="panel">
            <div className="empty">
              <b>{loadError}</b>
            </div>
          </div>
        ) : null}
        <div className="seg" role="tablist" aria-label="Compliance views" data-ui="compliance-tabs">
          <button type="button" role="tab" aria-selected={tab === "packs"} className={tab === "packs" ? "primary" : ""} onClick={() => setTab("packs")}>
            Framework packs
          </button>
          <button type="button" role="tab" aria-selected={tab === "desc"} className={tab === "desc" ? "primary" : ""} onClick={() => setTab("desc")}>
            DESC / UAE IA / CERT-In, clock and records
          </button>
          <button type="button" role="tab" aria-selected={tab === "requests"} className={tab === "requests" ? "primary" : ""} onClick={() => setTab("requests")} data-ui="compliance-tab-requests">
            Data requests
            {view?.dataRequests?.overdue ? ` · ${view.dataRequests.overdue} overdue` : ""}
          </button>
        </div>
        {tab === "requests" ? (
          <div className="mt">
            <DataRequests />
          </div>
        ) : null}
        {tab === "packs" ? (
          <div className="mt">
            <FrameworkPacks />
          </div>
        ) : null}
        {tab === "desc" && !view && !loadError ? <p className="muted">Loading…</p> : null}
        {tab === "desc" && view ? (
          <>
            <div className="kpis">
              {ORDER.map((status) => (
                <div className="kpi" key={status}>
                  <div className="k">{STATUS_LABELS[status]}</div>
                  <div className="v">{view.summary[status] ?? 0}</div>
                </div>
              ))}
            </div>
            <div className="panel mt">
              <h2>
                Controls <small>worked out from the settings in force</small>
              </h2>
              <div className="tw">
              <table data-ui="compliance-controls">
                <thead>
                  <tr>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Now</th>
                    <th>Who</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {controls.map((c) => (
                    <tr key={c.id} data-control={c.id}>
                      <td>
                        <b>{c.title}</b>
                        <span className="sub small muted">
                          {c.id} · {c.refs.join(" · ")}
                        </span>
                      </td>
                      <td className="nowrap">
                        <span className={`chip ${STATUS_CHIP[c.status]}`}>
                          <i />
                          {STATUS_LABELS[c.status]}
                        </span>
                      </td>
                      <td className="small">{c.detail}</td>
                      <td className="small nowrap">{OWNER_LABELS[c.owner]}</td>
                      <td className="small nowrap">
                        <Link href={c.evidence.href}>{c.evidence.label}</Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            </div>
            <div className="grid g2 mt">
              <div className="panel">
                <h2>Clock</h2>
                <p className="small">{clockSentence(view.clock)}</p>
                <dl className="kv">
                  <dt>Host clock (NTP)</dt>
                  <dd>{view.clock.kernel.synchronized === null ? "Not readable here" : view.clock.kernel.synchronized ? "Synchronised" : "Not synchronised"}</dd>
                  <dt>Checked against</dt>
                  <dd className="mono">{view.clock.ntpServer || "— (TIME_SYNC_NTP_SERVER)"}</dd>
                  <dt>Database clock</dt>
                  <dd>{view.clock.databaseSkewSeconds === null ? "—" : `${view.clock.databaseSkewSeconds} s from the API`}</dd>
                  <dt>Time zone for schedules</dt>
                  <dd className="mono">{view.clock.timeZone}</dd>
                </dl>
              </div>
              <div className="panel">
                <h2>Encryption at rest</h2>
                <dl className="kv">
                  <dt>Backups</dt>
                  <dd>{view.encryption.backups.encrypted ? `Encrypted (${view.encryption.backups.source === "passphrase" ? "BACKUP_PASSPHRASE" : "this server's backup key"})` : "Not encrypted (Settings → Backups & health)"}</dd>
                  <dt>Secrets</dt>
                  <dd className="small">{view.encryption.secrets.what}</dd>
                  <dt>Disk</dt>
                  <dd className="small">{view.encryption.disk.confirmed ? "Encrypted, as the customer confirmed (DISK_ENCRYPTION_CONFIRMED)." : view.encryption.disk.what}</dd>
                </dl>
              </div>
            </div>
            <div className="grid g2 mt">
              <form className="panel form" onSubmit={saveSettings} data-ui="compliance-settings">
                <h2>Records and residency</h2>
                <p className="small muted">
                  The audit log is never deleted. User activity and connector API activity are kept at least {view.settings.minRetentionDays} days (CERT-In); the services&apos; own log lines are kept by Docker by size, so forward them to your SIEM to keep them longer.
                </p>
                <label className="f">
                  User activity kept (days)
                  <input inputMode="numeric" value={form.activity} disabled={!view.mayChange} onChange={(e) => setForm((f) => ({ ...f, activity: e.target.value }))} />
                </label>
                <label className="f">
                  Connector API activity kept (days)
                  <input inputMode="numeric" value={form.connector} disabled={!view.mayChange} onChange={(e) => setForm((f) => ({ ...f, connector: e.target.value }))} />
                </label>
                <label className="f">
                  Data location (shown in About and in incident reports)
                  <input value={form.location} maxLength={200} disabled={!view.mayChange} placeholder={view.settings.dataLocationDefault || "Dubai, United Arab Emirates"} onChange={(e) => setForm((f) => ({ ...f, location: e.target.value }))} />
                </label>
                <label className="f">
                  Incident contact (name, email, phone)
                  <input value={form.contact} maxLength={320} disabled={!view.mayChange} onChange={(e) => setForm((f) => ({ ...f, contact: e.target.value }))} />
                </label>
                {view.mayChange ? (
                  <button className="btn mt" type="submit" disabled={busy}>
                    Save
                  </button>
                ) : (
                  <p className="small muted" data-ui="compliance-read-only">{view.readOnlyNote || "Owners and admins change these."}</p>
                )}
              </form>
              <div className="panel">
                <h2>Incident report</h2>
                <p className="small muted">
                  The security events of a time window (24 hours by default, at most 31 days), with the installation, the clock and each entry&apos;s sequence number and MAC, signed. Attach it to a report to DESC, or to CERT-In within 6 hours of noticing an incident.
                </p>
                <div className="flex">
                  <label className="f">
                    From
                    <input type="date" value={windowFrom} onChange={(e) => setWindowFrom(e.target.value)} />
                  </label>
                  <label className="f">
                    To
                    <input type="date" value={windowTo} onChange={(e) => setWindowTo(e.target.value)} />
                  </label>
                </div>
                <button className="btn mt" type="button" disabled={busy} onClick={report} data-ui="compliance-incident-report">
                  Download the incident report
                </button>
                <p className="small muted mt">
                  For a SIEM: Settings → Audit log → <b>Export CEF</b>.
                </p>
              </div>
            </div>
            <div className="panel mt">
              <h2>What the software cannot do</h2>
              <p className="small">
                DESC ISR and the UAE IA Standard are management-system standards: the entity running Hawk AI (and, as its supplier, the vendor) also needs an information security policy and ISMS, a risk assessment, asset inventory, HR security and awareness, supplier management, an incident response plan and team, business continuity and disaster recovery plans tested yearly, internal audit, and physical security of the server room. Hawk AI gives evidence for them (the audit log, exports, backups and restores, the incident report); it cannot be them.
              </p>
              <ul className="small">
                {view.standards.map((s) => (
                  <li key={s.key}>
                    <a href={s.url} target="_blank" rel="noreferrer noopener">
                      {s.name}
                    </a>{" "}
                    — {s.by}. {s.applies}
                  </li>
                ))}
              </ul>
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
