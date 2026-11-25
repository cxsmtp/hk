"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { INTEGRITY_NOTICE_CHANGED_EVENT } from "@/components/integrity-notice";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import {
  available,
  changedFiles,
  eventBad,
  eventLine,
  EVENTS,
  HOURS,
  INTEG,
  label,
  serverNow,
  SWITCHING_TEXT,
  updaterCallout,
  versionRow,
  visibleVersions,
} from "@/lib/updates-settings";
import type { Integrity, UpdatesStatus } from "@/lib/updates-settings";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const date = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "");
const dateTime = (iso?: string | null) =>
  iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short" }) : "—";
const num = (n?: number) => (Number.isFinite(n) ? Number(n).toLocaleString() : "0");

function DownloadIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3v12m0 0-4-4m4 4 4-4M5 21h14" />
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

/**
 * Settings → Updates, laid out and worded as FTR Command Center's Updates page (public/js/settings.js `updates()`): the
 * running version, the newest published one with Update now, auto-update, what this installation follows and its hour,
 * software integrity with Check now, Check for updates, the versions with Update now / Roll back to this, and the
 * recent events. What happens behind it is CxMissionZero's (docs/updating.md, docs/integrity.md): the updater takes a
 * backup, installs every image, and puts the previous version back by itself if the new one does not come up.
 * Owners and admins only.
 */
export default function UpdatesSettingsPage() {
  const [u, setU] = useState<UpdatesStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [shown, setShown] = useState(3);
  const [busy, setBusy] = useState("");
  const [switching, setSwitching] = useState<{ to: string; step: string } | null>(null);
  const polling = useRef(false);

  const load = useCallback(async () => {
    try {
      const status = await api.getUpdates();
      setU(status);
      setLoadError("");
      return status;
    } catch (error) {
      setLoadError(message(error));
      return null;
    }
  }, []);

  useEffect(() => {
    load()
      .then((status) => {
        // A check on open when the last one is older than 10 minutes (CxMissionZero MZ-01.00.36).
        const last = status?.lastCheck?.at ? Date.parse(status.lastCheck.at) : 0;
        if (status && Date.now() - last > 10 * 60_000) api.checkForUpdates().then(setU, () => undefined);
      })
      .catch(() => undefined);
  }, [load]);

  /** FTR's waitForRestart: follow the updater, then reload on the new version (or on the one put back). */
  const waitForSwitch = useCallback(
    async (to: string) => {
      if (polling.current) return;
      polling.current = true;
      setSwitching({ to, step: "Asking the updater" });
      for (let i = 0; i < 180; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        try {
          const status = await api.getUpdates();
          const job = status.updater.status;
          if (job?.step) setSwitching({ to, step: job.step });
          if (!status.updater.busy && job && job.state !== "running") {
            polling.current = false;
            if (job.state === "done") return window.location.reload();
            setSwitching(null);
            setU(status);
            toast.error(job.error || `${label(to)} was not installed (${job.state}).`);
            return;
          }
        } catch {
          // Hawk AI is restarting: keep waiting.
        }
      }
      polling.current = false;
      window.location.reload();
    },
    [],
  );

  useEffect(() => {
    if (u?.updater.busy && u.updater.status?.state === "running") waitForSwitch(u.updater.status.version || u.updater.pending?.version || "").catch(() => undefined);
  }, [u, waitForSwitch]);

  async function check() {
    setBusy("check");
    try {
      setU(await api.checkForUpdates());
    } catch (error) {
      toast.error(message(error));
    }
    setBusy("");
  }

  async function install(version: string, rollback: boolean) {
    if (rollback && !window.confirm(`Roll back to ${label(version)}? A backup is taken first. Going back to an older version can leave newer data it does not know; if it cannot read this database, it is not started and this version is put back.`)) return;
    setBusy(`v-${version}`);
    try {
      await api.installVersion(version);
      setBusy("");
      await waitForSwitch(version);
    } catch (error) {
      toast.error(message(error));
      setBusy("");
      await load();
    }
  }

  async function saveSettings(patch: { auto?: boolean; windowHour?: number | null; channel?: "latest" | "stable" }) {
    try {
      setU(await api.saveUpdateSettings(patch));
      toast.success("Saved.");
    } catch (error) {
      toast.error(message(error));
      await load();
    }
  }

  async function checkIntegrity() {
    setBusy("integ");
    try {
      const integrity: Integrity = await api.checkIntegrity();
      setU((current) => (current ? { ...current, integrity } : current));
      const bad = integrity.state === "tampered" || integrity.state === "not-genuine";
      window.dispatchEvent(new CustomEvent(INTEGRITY_NOTICE_CHANGED_EVENT, { detail: bad ? { state: integrity.state, summary: integrity.summary } : null }));
    } catch (error) {
      toast.error(message(error));
    }
    setBusy("");
  }

  async function restart() {
    if (!window.confirm("Restart Hawk AI? Each service finishes its work and starts again; people see “reconnecting…” for a few seconds.")) return;
    try {
      await api.restartHawk();
      toast.success("Restarting.");
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function report() {
    try {
      save(await api.downloadUpdateReport(), `hawk-ai-report-${new Date().toISOString().slice(0, 10)}.json`);
    } catch (error) {
      toast.error(message(error));
    }
  }

  const integ = u?.integrity;
  const [ic, il] = integ ? (INTEG[integ.state] ?? ["", integ.state]) : ["", ""];
  const o = integ?.origin?.ok ? integ.origin : null;
  const avail = u ? available(u) : null;
  const newest = u?.lastCheck?.versions?.[0] ?? null;
  const lastSwitch = u?.events.find((e) => e.type === "switch" && e.to === u.running.version);
  const callout = u ? updaterCallout(u.updater) : "";
  const canInstall = Boolean(u?.updater.connected && u.updater.manages);
  const settings = u?.settings;
  const inWindow = !settings || settings.windowHour === null || u?.serverTime.hour === settings.windowHour;
  const versions = u?.lastCheck?.versions ?? [];
  const page = u ? visibleVersions(versions, u.running.version, shown) : { rows: [], more: 0 };
  const changed = integ ? changedFiles(integ) : "";

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-updates">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Updates</h1>
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
          {!u && !loadError ? <p className="muted">Loading…</p> : null}
          {switching ? (
            <div className="loading" data-ui="switching">
              <div className="orbit">
                <i />
                <i />
                <i />
              </div>
              <b>Switching to {label(switching.to)}…</b>
              <span className="muted">{SWITCHING_TEXT}</span>
              <span className="small">{switching.step}</span>
            </div>
          ) : null}
          {u && integ && settings && !switching ? (
            <>
              <div className="saved-banner">✓ Changes save as you type.</div>
              <div className="panel">
                <h2>Update &amp; recovery</h2>
                <div className="ur-cards">
                  <div className="ur-card">
                    <small>Running</small>
                    <b>{u.running.label}</b>
                    <span>{u.updater.manages ? `Published images (${u.image}-…)` : "Built from this checkout"}</span>
                    {lastSwitch ? (
                      <span className="faint">
                        Switched to it {dateTime(lastSwitch.at)}
                        {lastSwitch.automatic ? " · auto-update" : lastSwitch.by ? ` · ${lastSwitch.by}` : ""}
                      </span>
                    ) : null}
                  </div>
                  <div className="ur-card">
                    <small>Latest published</small>
                    <b>{u.latest ? label(u.latest.version) : newest ? label(newest.version) : "—"}</b>
                    <span>
                      {avail ? `${label(avail.version)} is ready.` : "Up to date."} {u.lastCheck?.at ? `Checked ${dateTime(u.lastCheck.at)}` : "Not checked yet"}
                    </span>
                    {avail && canInstall ? (
                      <button className="sm primary mt" type="button" data-update-now={avail.version} disabled={Boolean(busy)} onClick={() => install(avail.version, false)}>
                        {busy === `v-${avail.version}` ? <span className="spinner" /> : null}
                        {busy === `v-${avail.version}` ? "Updating…" : "Update now"}
                      </button>
                    ) : null}
                    {u.lastCheck?.error ? <span className="bad-t">Last try: {u.lastCheck.error}</span> : null}
                  </div>
                  <div className="ur-card">
                    <small>Auto-update</small>
                    <b className={settings.auto ? "ok-t" : "off-t"}>{settings.auto ? `Following ${settings.channel}` : "Off"}</b>
                    <form id="auto" className="inline-num" onSubmit={(e) => e.preventDefault()}>
                      <label className="inline-num">
                        <input type="checkbox" name="auto" checked={settings.auto} onChange={(e) => saveSettings({ auto: e.target.checked })} /> Install new versions by itself
                      </label>
                    </form>
                    <span className="faint" id="auto-saved">
                      {settings.lastAutoResult
                        ? `${settings.lastAutoAt ? `${dateTime(settings.lastAutoAt)}: ` : ""}${settings.lastAutoResult}.`
                        : "A minute after start, then every 15 minutes; a version that fails to start is rolled back and never installed again by itself."}
                    </span>
                  </div>
                </div>
                <form id="stage" className="stage-box" data-nodraft onSubmit={(e) => e.preventDefault()}>
                  <div className="stage-h">
                    <b>This installation follows</b>
                    <span className="seg stage-seg" role="radiogroup" aria-label="What this installation follows">
                      {(
                        [
                          ["latest", "Latest"],
                          ["stable", "Stable"],
                        ] as const
                      ).map(([value, text]) => (
                        <label key={value} className={settings.channel === value ? "on" : ""}>
                          <input type="radio" name="channel" value={value} checked={settings.channel === value} onChange={() => saveSettings({ channel: value })} />
                          {text}
                        </label>
                      ))}
                    </span>
                    <span className="faint" id="stage-saved" />
                  </div>
                  <p className="muted small">
                    {settings.channel === "stable" ? (
                      <>
                        <b>Stable:</b> the release the maintainer promoted, after it was looked at. Update now and auto-update install it; every other version can still be installed or rolled back to below.
                      </>
                    ) : (
                      <>
                        <b>Latest:</b> every merged release, as soon as every test has passed. Choose <b>Stable</b> for production, where a release should have been looked at first.
                      </>
                    )}
                  </p>
                  <div className="stage-win">
                    <span>Update by itself only in the hour from</span>
                    <select
                      name="windowHour"
                      aria-label="Hour"
                      value={settings.windowHour === null ? "" : String(settings.windowHour)}
                      onChange={(e) => saveSettings({ windowHour: e.target.value === "" ? null : Number(e.target.value) })}
                    >
                      {HOURS.map((h) => (
                        <option key={h.value} value={h.value}>
                          {h.text}
                        </option>
                      ))}
                    </select>
                    <span className="faint">
                      server time, now {serverNow(u.serverTime)}. Any time: as soon as a release is found. Installing by hand is never held back.
                      {settings.windowHour !== null && !inWindow && avail ? <b> {label(avail.version)} is waiting for this hour.</b> : null}
                    </span>
                  </div>
                </form>
                <div className="integ" data-ui="integrity">
                  <div className="integ-h">
                    <b>Software integrity</b>
                    <span className={`chip ${ic}`}>
                      <i />
                      {il}
                    </span>
                    <span className="spacer" />
                    <button className="sm" type="button" id="integ-check" disabled={busy === "integ"} onClick={checkIntegrity}>
                      {busy === "integ" ? <span className="spinner" /> : null}
                      {busy === "integ" ? "Checking…" : "Check now"}
                    </button>
                  </div>
                  <p>{integ.summary}</p>
                  {integ.digest ? (
                    <dl className="kv">
                      <dt>Version</dt>
                      <dd>{integ.version ? label(integ.version) : "—"}</dd>
                      {o ? (
                        <>
                          <dt>Built from</dt>
                          <dd>
                            <a href={`https://github.com/${o.repository}/commit/${o.commit}`} target="_blank" rel="noopener noreferrer">
                              {o.repository} · {String(o.ref ?? "").replace(/^refs\/(heads|tags)\//, "")} · {String(o.commit ?? "").slice(0, 12)}
                            </a>
                          </dd>
                          <dt>Workflow run</dt>
                          <dd>
                            {/^https:\/\/github\.com\//.test(o.run ?? "") ? (
                              <a href={o.run} target="_blank" rel="noopener noreferrer">
                                {String(o.run).replace("https://github.com/", "")}
                              </a>
                            ) : (
                              (o.run ?? "")
                            )}
                          </dd>
                          <dt>Signed</dt>
                          <dd>
                            {dateTime(o.signedAt)}
                            {Number.isFinite(o.logIndex) ? (
                              <>
                                {" · "}
                                <a href={`https://search.sigstore.dev/?logIndex=${o.logIndex}`} target="_blank" rel="noopener noreferrer">
                                  Sigstore log entry {o.logIndex}
                                </a>
                              </>
                            ) : null}
                          </dd>
                        </>
                      ) : null}
                      <dt>Files</dt>
                      <dd>
                        {num(integ.files?.checked)} checked
                        {integ.files && !integ.files.ok ? ` · ${num(integ.files.counts.changed)} changed, ${num(integ.files.counts.missing)} missing, ${num(integ.files.counts.extra)} added` : ""}
                      </dd>
                      <dt>File list SHA-256</dt>
                      <dd className="mono small">{integ.digest}</dd>
                      <dt>Checked</dt>
                      <dd>{dateTime(integ.at)}</dd>
                    </dl>
                  ) : null}
                  {changed ? <p className="small bad-t">{changed}</p> : null}
                </div>
                {callout ? <div className="callout warn mt">{callout}</div> : null}
                {u.updater.busy && u.updater.status?.state === "running" ? <div className="callout mt">An update is under way: {u.updater.status.step}</div> : null}
                {u.lastCheck?.warning ? <div className="callout warn mt">{u.lastCheck.warning}</div> : null}
                <div className="flex mt">
                  <button className="primary" type="button" id="chk" disabled={busy === "check"} onClick={check}>
                    {busy === "check" ? <span className="spinner" /> : null}
                    {busy === "check" ? "Checking…" : "Check for updates"}
                  </button>
                  {canInstall ? (
                    <button type="button" id="restart" onClick={restart}>
                      Restart Hawk AI
                    </button>
                  ) : null}
                  <button type="button" id="diag2" onClick={report}>
                    <DownloadIcon />
                    Download troubleshooting report
                  </button>
                </div>
              </div>
              <div className="grid g2 mt">
                <div className="panel wide-panel">
                  <h2>
                    Versions <small>every published version, newest first: update or roll back from here</small>
                  </h2>
                  {versions.length ? (
                    <>
                      <div className="tw">
                        <table className="versions" id="versions-t">
                          <thead>
                            <tr>
                              <th>Version</th>
                              <th>Image digest</th>
                              <th>Built</th>
                              <th>State</th>
                              <th />
                            </tr>
                          </thead>
                          <tbody>
                            {page.rows.map((v) => {
                              const row = versionRow(v, u);
                              return (
                                <tr key={v.version} data-v={v.version}>
                                  <td>
                                    <b>{v.label}</b>
                                    <span className="sub">
                                      {v.version}
                                      {v.revision ? ` · commit ${v.revision}` : ""}
                                    </span>
                                  </td>
                                  <td>
                                    <code className="small" title={v.digest}>
                                      {v.digest.replace("sha256:", "").slice(0, 12)}…{v.digest.slice(-6)}
                                    </code>
                                  </td>
                                  <td className="small">{date(v.created)}</td>
                                  <td>
                                    {row.chips.map(([kind, text]) => (
                                      <span key={text} className={`chip ${kind}`}>
                                        <i />
                                        {text}
                                      </span>
                                    ))}
                                  </td>
                                  <td className="actions">
                                    {row.action === "update" ? (
                                      <button className="sm primary" type="button" data-act="update" disabled={Boolean(busy)} onClick={() => install(v.version, false)}>
                                        {busy === `v-${v.version}` ? "Updating…" : "Update now"}
                                      </button>
                                    ) : row.action === "rollback" ? (
                                      <button className="sm" type="button" data-act="rollback" data-rollback="1" disabled={Boolean(busy)} onClick={() => install(v.version, true)}>
                                        {busy === `v-${v.version}` ? "Switching…" : "Roll back to this"}
                                      </button>
                                    ) : row.why ? (
                                      <span className="muted small">{row.why}</span>
                                    ) : null}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                      {page.more ? (
                        <button type="button" className="link mt" id="v-more" onClick={() => setShown((n) => n + 10)}>
                          Load {Math.min(10, page.more)} more ▾
                        </button>
                      ) : null}
                    </>
                  ) : (
                    <div className="empty">
                      <b>No versions yet</b>Check for updates.
                    </div>
                  )}
                  <p className="muted small mt">
                    <b>Update now</b> installs a newer release and <b>Roll back to this</b> an older one, the same way: a backup is taken first, every image is checked against what the release workflow
                    signed, and if the version does not come up within 150 s the one before is put back by itself, with its data. A version that failed to start is never installed again by
                    itself.
                  </p>
                </div>
                <div className="panel">
                  <h2>Recent events</h2>
                  {u.events.length ? (
                    <div className="tw">
                      <table>
                        <tbody>
                          {u.events.map((e) => (
                            <tr key={`${e.at}-${e.type}`}>
                              <td className="small">{dateTime(e.at)}</td>
                              <td>
                                <span className={`chip ${eventBad(e.type) ? "bad" : "ok"}`}>
                                  <i />
                                  {EVENTS[e.type] ?? e.type}
                                </span>
                              </td>
                              <td className="small">{eventLine(e)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="muted">Nothing yet.</p>
                  )}
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
