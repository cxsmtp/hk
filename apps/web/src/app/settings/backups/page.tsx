"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { ServerSettingNote } from "@/components/server-setting-note";
import { api } from "@/lib/api";
import { useInstallationAdmin } from "@/lib/settings-console";
import { BACKUP_NOTICE_CHANGED_EVENT } from "@/components/backup-notice";
import { SelfCheckBox } from "@/components/self-check-box";
import { backupKeyFile, backupsHeading, beforeUpdateLine, kb, READINESS, restoreQuestion, sealedLine } from "@/lib/backups-settings";
import type { BackupEncryption, BackupKeyShown, BackupsStatus, Readiness } from "@/lib/backups-settings";
import type { SelfCheckHealth } from "@/lib/hands-off-settings";
import { errorMessageFrom } from "@/lib/licence";
import { bundleFileName, historyLine, recoveryChip, STATUS_TONE } from "@/lib/self-recovery";
import type { DiagnosticsView } from "@/lib/self-recovery";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");

/** The same troubleshooting report as Settings → Updates (versions, health, settings in force, recent errors; no secrets). */
async function downloadReport() {
  try {
    const blob = await api.downloadUpdateReport();
    const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `hawk-ai-report-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
  } catch (error) {
    toast.error(message(error));
  }
}
const date = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");
const dateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—");

function Icon({ name }: { name: "plus" | "download" }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      {name === "plus" ? <path d="M12 5v14M5 12h14" /> : <path d="M12 3v12m0 0-4-4m4 4 4-4M5 21h14" />}
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

/** Tell the notice at the top of every page (components/backup-notice.tsx) that it changed. */
const noticeChanged = (encryption: BackupEncryption) => window.dispatchEvent(new CustomEvent(BACKUP_NOTICE_CHANGED_EVENT, { detail: encryption.notice }));

/**
 * Settings → Backups & health, laid out and worded as FTR Command Center's (public/js/settings.js `backups()`): the
 * backups (now, each to download, a restore) and the health of the data, then "Ready for production?". What happens
 * behind it is CxMissionZero's (/settings/guide/audit-and-evidence), and so is the backup key box, which stands where FTR's
 * passphrase form stands. Owners and admins only.
 */
export default function BackupsSettingsPage() {
  // Backups, the backup key and restore are the whole server's: a workspace admin who is not one of its
  // administrators reads them only. Diagnostics below stay theirs (their own workspace's bundle).
  const readOnly = useInstallationAdmin() === false;
  const [b, setB] = useState<BackupsStatus | null>(null);
  const [rd, setRd] = useState<Readiness | null>(null);
  const [loadError, setLoadError] = useState("");
  const [shown, setShown] = useState<BackupKeyShown | null>(null);
  const [keyErr, setKeyErr] = useState("");
  const [rsres, setRsres] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const [pass, setPass] = useState("");
  const [health, setHealth] = useState<SelfCheckHealth | null>(null);
  const [checking, setChecking] = useState(false);
  const [diag, setDiag] = useState<DiagnosticsView | null>(null);
  const [recovering, setRecovering] = useState(false);

  const load = useCallback(async () => {
    try {
      const [status, ready, selfCheck, diagnostics] = await Promise.all([api.getBackups(), api.getReadiness().catch(() => null), api.getSelfCheck().catch(() => null), api.getDiagnostics().catch(() => null)]);
      setB(status);
      setDiag(diagnostics);
      setRd(ready);
      setHealth(selfCheck?.health ?? null);
      setLoadError("");
      if (status.encryption.source !== "key") setShown(null);
    } catch (error) {
      setLoadError(message(error));
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  async function now() {
    setBusy(true);
    await api.backUpNow().then(
      () => toast.success("Backed up."),
      (error) => toast.error(message(error)),
    );
    setBusy(false);
    await load();
  }

  async function download(name: string) {
    try {
      save(await api.downloadBackup(name), name);
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function showKey() {
    setKeyErr("");
    try {
      setShown(await api.showBackupKey());
    } catch (error) {
      setKeyErr(message(error));
    }
  }

  async function turnOn() {
    if (!window.confirm("Turn on backup encryption? The server makes a backup key and encrypts every backup from now on. You will be shown the key: keep it somewhere other than this server, because a backup opens only with it.")) return;
    try {
      const { encryption } = await api.turnOnBackupEncryption();
      noticeChanged(encryption);
      await showKey();
      await load();
    } catch (error) {
      setKeyErr(message(error));
    }
  }

  async function copyKey() {
    if (!shown) return;
    try {
      await navigator.clipboard.writeText(shown.key);
      toast.success("Backup key copied.");
    } catch {
      toast("Select the key and copy it.");
    }
  }

  async function confirmSaved() {
    if (!window.confirm("Have you saved the backup key somewhere other than this server? Without it, a backup cannot be opened if this server is lost.")) return;
    try {
      const { encryption } = await api.confirmBackupKey();
      setShown(null);
      noticeChanged(encryption);
      await load();
    } catch (error) {
      setKeyErr(message(error));
    }
  }

  async function restore(event: FormEvent) {
    event.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return setRsres("Choose a backup file.");
    try {
      const { backup: info } = await api.restoreBackup(file, pass, true);
      if (!window.confirm(restoreQuestion(info, dateTime))) return;
      const r = await api.restoreBackup(file, pass, false);
      setRsres(r.staged ? "Checked and staged. Restart the server to restore it (docker compose -f deploy/compose.yaml stop api worker beat, then sudo deploy/install.sh): it is applied before anything else starts." : "Restored. Restart the server to read it.");
      setPass("");
      if (fileRef.current) fileRef.current.value = "";
      await load();
    } catch (error) {
      setRsres(message(error));
    }
  }

  async function cancelRestore() {
    try {
      await api.cancelRestore();
      toast.success("The staged restore is cancelled.");
      await load();
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function checkNow() {
    setChecking(true);
    try {
      setHealth((await api.checkNow()).health);
    } catch (error) {
      toast.error(message(error));
    } finally {
      setChecking(false);
    }
  }

  /** The diagnostics bundle (signed manifest, redacted logs and settings): to send to the OEM. */
  async function downloadBundle(prepared = false) {
    try {
      const { blob, disposition } = await api.downloadDiagnosticsBundle(prepared);
      save(blob, bundleFileName(disposition));
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function recoverNow() {
    setRecovering(true);
    try {
      setDiag(await api.runSelfRecovery());
    } catch (error) {
      toast.error(message(error));
    } finally {
      setRecovering(false);
    }
  }

  async function tryAgain(reference: string) {
    try {
      setDiag(await api.retrySelfRecovery(reference));
      toast.success(`${reference}: Hawk AI tries again at its next run.`);
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function accept(id: string, yes: boolean) {
    await api.setReadiness(id, yes).then(
      () => toast.success(yes ? "Kept as meant." : "It is asked again."),
      (error) => toast.error(message(error)),
    );
    await load();
  }

  const e = b?.encryption;
  const sealed = b ? sealedLine(b) : null;
  const chip = recoveryChip(diag);

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-backups">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Backups &amp; health</h1>
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
          {!b && !loadError ? <p className="muted">Loading…</p> : null}
          {b && e && sealed ? (
            <>
              <ServerSettingNote readOnly={readOnly} />
              <div className="grid g2">
                <fieldset className="ro-fieldset" disabled={readOnly} data-ui="backups-server">
                <div className="panel">
                  <h2>
                    Backups <small>{backupsHeading(b)}</small>
                  </h2>
                  <p className="muted small">
                    Everything: people, organisations, settings, certificates and the audit log (the whole database and the API&apos;s data folder).{" "}
                    {sealed.warn ? (
                      <>
                        <b className="warn-t">Not sealed:</b> {sealed.text}
                      </>
                    ) : (
                      sealed.text
                    )}{" "}
                    Kept in <span className="mono">{b.dir}</span>.
                  </p>
                  {b.separate ? (
                    <div className="callout">Backups go to their own place (BACKUP_DIR), away from the data: losing one disk does not lose both.</div>
                  ) : (
                    <div className="callout warn">
                      Backups are in the data volume itself. Mount a second volume or a network share and set <b>BACKUP_DIR</b> to it, so losing one disk does not lose both.
                    </div>
                  )}
                  {b.last && !b.last.ok ? (
                    <div className="callout warn mt">
                      The last backup failed ({dateTime(b.last.at)}): {b.last.error}
                    </div>
                  ) : null}
                  {beforeUpdateLine(b) ? (
                    <p className="muted small">
                      {beforeUpdateLine(b)} <a href="/settings/updates">Settings → Updates</a>
                    </p>
                  ) : null}
                  <div className="flex">
                    <button className="primary" id="now" type="button" disabled={busy} onClick={now}>
                      <Icon name="plus" />
                      Back up now
                    </button>
                  </div>

                  {e.source === "passphrase" ? null : (
                    <div className={`form mt callout ${e.notice ? "warn" : ""}`} id="backup-key-panel" data-source={e.source}>
                      {e.source === "none" ? (
                        <>
                          <b>Backups are not encrypted.</b>
                          {e.optedOut ? (
                            <span className="small">
                              BACKUP_ENCRYPTION=off is set on the server. Each backup holds the password hashes, the connector keys and the certificate keys in the clear. To encrypt them, remove that setting and restart the server.
                            </span>
                          ) : (
                            <>
                              <span className="small">
                                Each backup holds the password hashes, the connector keys and the certificate keys in the clear. Turn encryption on and the server makes a backup key, shows it to you, and encrypts every backup from then on. Backups made before stay as they are.
                              </span>
                              <div className="flex">
                                <button type="button" id="backup-encrypt-on" className="sm" onClick={turnOn}>
                                  Turn on backup encryption
                                </button>
                              </div>
                            </>
                          )}
                        </>
                      ) : (
                        <>
                          <b>Backup key</b>
                          <span className="small">
                            Every backup is encrypted with this server&apos;s backup key. Keep the key somewhere other than this server: if the server is lost, a backup opens only with it. To restore on another server, give the key when the restore asks, or set BACKUP_PASSPHRASE to it. The key is never emailed and is not inside a backup.
                          </span>
                          {shown ? (
                            <>
                              <code className="mono" id="backup-key-value">
                                {shown.key}
                              </code>
                              <div className="flex">
                                <button type="button" id="backup-key-copy" className="sm" onClick={copyKey}>
                                  Copy
                                </button>
                                <button type="button" id="backup-key-download" className="sm" onClick={() => save(new Blob([backupKeyFile(shown)], { type: "text/plain" }), "hawk-ai-backup-key.txt")}>
                                  Download as a text file
                                </button>
                                <button type="button" id="backup-key-hide" className="sm ghost" onClick={() => setShown(null)}>
                                  Hide
                                </button>
                              </div>
                            </>
                          ) : (
                            <div className="flex">
                              <button type="button" id="backup-key-show" className="sm" onClick={showKey}>
                                Show backup key
                              </button>
                            </div>
                          )}
                          {e.keySaved ? (
                            <span className="small muted">
                              Saved somewhere else: confirmed {dateTime(e.keySavedAt)}
                              {e.keySavedBy ? ` by ${e.keySavedBy}` : ""}.
                            </span>
                          ) : (
                            <span className="small">
                              <b>Nobody has confirmed saving this key yet.</b> Show it, keep a copy somewhere other than this server (a password manager, a safe), then confirm.
                            </span>
                          )}
                          {shown && !e.keySaved ? (
                            <div className="flex">
                              <button type="button" id="backup-key-confirm" className="sm" onClick={confirmSaved}>
                                I have saved it
                              </button>
                            </div>
                          ) : null}
                        </>
                      )}
                      {keyErr ? (
                        <span className="err" role="alert">
                          {keyErr}
                        </span>
                      ) : null}
                    </div>
                  )}

                  <div className="tw mt">
                    <table>
                      <tbody>
                        {b.backups.length ? (
                          b.backups.map((x) => (
                            <tr key={x.name}>
                              <td className="small mono">{x.name}</td>
                              <td className="small">{dateTime(x.at)}</td>
                              <td className="num small">{kb(x.bytes)}</td>
                              <td className="actions">
                                <button className="sm ghost" type="button" data-dl={x.name} onClick={() => download(x.name)}>
                                  <Icon name="download" />
                                  Download
                                </button>
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td>
                              <div className="empty">
                                <b>No backups yet</b>
                              </div>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  <h3 className="mt">Restore</h3>
                  {b.pendingRestore ? (
                    <div className="callout warn">
                      A restore is staged: it is applied when Hawk AI next starts, before anything else runs.{" "}
                      <button type="button" className="sm ghost" id="rscancel" onClick={cancelRestore}>
                        Cancel it
                      </button>
                    </div>
                  ) : null}
                  <form className="form" id="rs" onSubmit={restore}>
                    <label className="f">
                      A backup file
                      <input ref={fileRef} type="file" name="file" accept=".hkbackup" />
                    </label>
                    <label className="f">
                      Its passphrase <span className="muted">if sealed</span>
                      <input type="password" name="pass" autoComplete="off" value={pass} onChange={(event) => setPass(event.target.value)} />
                    </label>
                    <div className="flex">
                      <button type="submit" className="danger">
                        Check and restore
                      </button>
                    </div>
                    <div className="small" id="rsres" role="status">
                      {rsres}
                    </div>
                  </form>
                </div>
                </fieldset>

                <div className="panel">
                  <h2>Health</h2>
                  <div id="self-check">
                    <SelfCheckBox health={health} onCheck={checkNow} busy={checking} readOnly={readOnly} />
                    <p className="muted small">
                      Who hears about problems, the weekly status and replies by email: <a href="/settings/hands-off">Settings → Hands-off</a>.
                    </p>
                  </div>
                  {b.recovered.length ? (
                    <>
                      <h3>Repaired at start</h3>
                      <ul className="small">
                        {b.recovered.map((r) => (
                          <li key={`${r.target}-${r.details.kept}`}>
                            {dateTime(r.at)}: <span className="mono">{r.target}</span> could not be read and was restored from {r.details.backup} (the damaged file is kept as {r.details.kept})
                          </li>
                        ))}
                      </ul>
                    </>
                  ) : (
                    <p className="small muted">Every data file is checked at start; one that cannot be read is restored from its last good copy. Nothing needed repairing.</p>
                  )}
                  <p className="muted small">The troubleshooting report has versions, health, settings in force, update events, backups and recent errors, and no secrets, keys or customer data.</p>
                  <div className="flex">
                    <button id="diag" type="button" onClick={downloadReport}>
                      <Icon name="download" />
                      Download troubleshooting report
                    </button>
                  </div>
                </div>
              </div>
              <div className="panel wide-panel mt" id="diagnostics">
                <h2>
                  Self-recovery <small>{diag ? (diag.scope === "installation" ? "the whole installation" : "your organisation, and the installation's issues in plain words") : ""}</small>
                </h2>
                <p>
                  <span className={`chip ${chip.tone}`}>
                    <i />
                    {chip.label}
                  </span>{" "}
                  {chip.text}
                </p>
                <p className="muted small">
                  Every {diag?.everyMinutes ?? 5} minutes Hawk AI reads its error log and its failed jobs, recognises the failures it knows and puts them right: it runs a failed job again, clears a stale lock, reconnects to the database or Redis, restarts a stuck worker or scheduler, frees disk space, checks the database schema again, and rolls a failed or unhealthy update back to the version before. Each fix has a limit; when it runs out, or the failure is one Hawk AI does not know, it stops trying and marks it <b>Needs OEM help</b>.
                  {diag?.lastRunAt ? ` Last run: ${dateTime(diag.lastRunAt)}.` : ""}
                </p>
                {diag?.issues.length ? (
                  <div className="tw">
                    <table className="ready-table" id="recovery-issues">
                      <thead>
                        <tr>
                          <th>Issue</th>
                          <th>State</th>
                          <th>What Hawk AI did</th>
                          <th>Reference</th>
                        </tr>
                      </thead>
                      <tbody>
                        {diag.issues.map((i) => (
                          <tr key={i.reference}>
                            <td>
                              <b>{i.title}</b>
                              {i.detail ? <div className="small muted">{i.detail}</div> : null}
                              <div className="small muted">since {dateTime(i.firstSeen)}</div>
                            </td>
                            <td data-v={i.statusLabel}>
                              <span className={`chip ${STATUS_TONE[i.status] ?? "warn"}`}>
                                <i />
                                {i.statusLabel}
                              </span>
                            </td>
                            <td className="small">
                              {i.lastAction ? `${i.lastAction} (${i.attempts} of ${i.limit}): ${i.lastResult ?? ""}` : i.limit ? `${i.action} (at most ${i.limit})` : i.action}
                            </td>
                            <td>
                              <span className="ready-act">
                                <span className="mono small">{i.reference}</span>
                                {diag.canRun && i.status === "needs_oem" ? (
                                  <button className="ghost sm" type="button" data-retry={i.reference} onClick={() => tryAgain(i.reference)}>
                                    Try again
                                  </button>
                                ) : null}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
                <h3 className="mt">Self-recovery history</h3>
                {diag?.history.length ? (
                  <ul className="small" id="recovery-history">
                    {diag.history.slice(0, 15).map((h, n) => (
                      <li key={`${h.at}-${h.reference}-${n}`}>{historyLine(h, dateTime)}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="small muted">Nothing yet: Hawk AI has not needed to put anything right.</p>
                )}
                <p className="muted small">
                  The diagnostics bundle is one file to send to the OEM: recent errors, failed jobs, update and rollback history, the self-check&apos;s and self-recovery&apos;s events, versions, health and the settings in force, with every secret, key and password taken out and no prompt text or customer data. Its manifest lists each file with its SHA-256 and is signed with this server&apos;s evidence key, so the OEM can check it came from here. {diag?.scope === "tenant" ? "Yours covers your organisation only." : ""}
                </p>
                <div className="flex">
                  <button id="bundle" type="button" className="primary" onClick={() => downloadBundle(false)}>
                    <Icon name="download" />
                    Download diagnostics bundle
                  </button>
                  {diag?.prepared ? (
                    <button id="bundle-prepared" type="button" className="ghost" onClick={() => downloadBundle(true)}>
                      <Icon name="download" />
                      Bundle prepared {dateTime(diag.prepared.at)}
                      {diag.prepared.reference ? ` (${diag.prepared.reference})` : ""}
                    </button>
                  ) : null}
                  {diag?.canRun ? (
                    <button id="recover-now" type="button" className="ghost" disabled={recovering} onClick={recoverNow}>
                      Run self-recovery now
                    </button>
                  ) : null}
                </div>
              </div>
              {rd ? (
                <div className="panel wide-panel mt" id="ready">
                  <h2>
                    Ready for production?{" "}
                    <small>
                      {rd.todo ? `${rd.todo} to do` : "nothing left to do"}
                      {rd.notes ? ` · ${rd.notes} to check` : ""}
                    </small>
                  </h2>
                  <p className="muted small">What to put right before the server is opened to more people, and where. Looking changes nothing.</p>
                  <div className="tw">
                    <table className="ready-table">
                      <thead>
                        <tr>
                          <th>Check</th>
                          <th>State</th>
                          <th>What was found</th>
                          <th>Where</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rd.checks.map((c) => (
                          <tr key={c.id}>
                            <td>
                              <b>{c.title}</b>
                            </td>
                            <td data-v={READINESS[c.state][1]}>
                              <span className={`chip ${READINESS[c.state][0]}`}>
                                <i />
                                {READINESS[c.state][1]}
                              </span>
                            </td>
                            <td className="small">{c.detail}</td>
                            <td>
                              <span className="ready-act">
                                {c.where && c.state !== "ok" ? (
                                  <a className="btn ghost sm" href={c.where}>
                                    Open
                                  </a>
                                ) : null}
                                {c.canAccept && c.state !== "ok" && !readOnly ? (
                                  <button className="ghost sm" type="button" data-accept={c.id} title="It is as you mean it: shown as ready until what was found changes" onClick={() => accept(c.id, true)}>
                                    As meant
                                  </button>
                                ) : null}
                                {c.accepted ? (
                                  <>
                                    <span className="muted small">
                                      as meant: {c.accepted.by}, {date(c.accepted.at)}
                                    </span>
                                    {readOnly ? null : (
                                      <button className="ghost sm" type="button" data-ask={c.id} onClick={() => accept(c.id, false)}>
                                        Ask again
                                      </button>
                                    )}
                                  </>
                                ) : null}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
