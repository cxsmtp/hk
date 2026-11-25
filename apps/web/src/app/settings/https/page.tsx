"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import {
  acmeLine,
  asksToConfirm,
  certificateChip,
  certificateIssues,
  hstsAgeLabel,
  MODE_LABELS,
  MODES,
  modeChip,
  requestNames,
  sourceLabel,
  splitNames,
} from "@/lib/https-settings";
import type { HttpsCertificateReport, HttpsMode, HttpsStatus, UploadFile } from "@/lib/https-settings";
import { errorMessageFrom } from "@/lib/licence";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const date = (iso?: string) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");
const dateTime = (iso?: string) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—");

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] ?? "");
    reader.onerror = () => reject(new Error(`${file.name} could not be read.`));
    reader.readAsDataURL(file);
  });
}

type Hardening = { minVersion: string; maxAge: number; hsts: boolean; sub: boolean };
const hardeningOf = (h: HttpsStatus): Hardening => ({ minVersion: h.minVersion, maxAge: h.hsts.maxAge, hsts: h.hsts.enabled, sub: h.hsts.includeSubDomains });

/**
 * Settings → HTTPS, laid out and worded as FTR Command Center's (public/js/settings.js `https()`): how the server is
 * reached (the three modes) and its hardening, the certificate in use with its upload and the request (CSR) for IT,
 * and a free certificate from Let's Encrypt. What happens behind it is CxMissionZero's (docs/https-and-hosting.md).
 * Owners and admins only.
 */
export default function HttpsSettingsPage() {
  const [h, setH] = useState<HttpsStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [err, setErr] = useState("");
  const [hard, setHard] = useState<Hardening | null>(null);
  const good = useRef<Hardening | null>(null);
  const [hardSaved, setHardSaved] = useState<{ text: string; bad: boolean }>({ text: "Saved as you change it.", bad: false });
  const [upres, setUpres] = useState<{ report?: HttpsCertificateReport; text?: string } | null>(null);
  const filesRef = useRef<HTMLInputElement>(null);
  const [pass, setPass] = useState("");
  const [csrNames, setCsrNames] = useState("");
  const [csrOrg, setCsrOrg] = useState("");
  const [le, setLe] = useState({ names: "", email: "", agree: false, staging: false });

  const load = useCallback(async () => {
    try {
      const status = await api.getHttps();
      setH(status);
      setHard(hardeningOf(status));
      good.current = hardeningOf(status);
      setCsrNames(requestNames(status));
      const a = status.acme;
      setLe((current) => ({ ...current, names: (a.last?.names ?? a.suggested ?? []).join(", "), email: a.email ?? "" }));
      setLoadError("");
    } catch (error) {
      setLoadError(message(error));
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  async function switchMode(mode: HttpsMode) {
    setErr("");
    try {
      await api.setHttpsMode(mode);
    } catch (error) {
      const text = message(error);
      if (!(asksToConfirm(text) && window.confirm(text))) return setErr(text);
      try {
        await api.setHttpsMode(mode, true);
      } catch (again) {
        return setErr(message(again));
      }
    }
    toast.success(`Now ${MODE_LABELS[mode]}.`);
    await load();
  }

  async function saveHardening(next: Hardening) {
    setHard(next);
    setHardSaved({ text: "Saving…", bad: false });
    try {
      await api.setHttpsHardening({ minVersion: next.minVersion, hsts: { enabled: next.hsts, includeSubDomains: next.sub, maxAge: Number(next.maxAge) } });
      good.current = next;
      setHardSaved({ text: `All changes are saved ✓ ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`, bad: false });
    } catch (error) {
      // The last good setting stays: on the server, and in the form.
      if (good.current) setHard(good.current);
      const text = message(error);
      setHardSaved({ text: `${text}${/back\.|kept\./.test(text) ? "" : " The last good setting is kept."}`, bad: true });
    }
  }

  async function chosenFiles(): Promise<UploadFile[]> {
    const list = [...(filesRef.current?.files ?? [])];
    return Promise.all(list.map(async (file) => ({ name: file.name, data: await fileToBase64(file) })));
  }

  async function inspect() {
    try {
      setUpres({ report: await api.inspectHttpsCertificate(await chosenFiles(), pass) });
    } catch (error) {
      setUpres({ text: message(error) });
    }
  }

  async function install(event: FormEvent) {
    event.preventDefault();
    const files = await chosenFiles();
    try {
      await api.installHttpsCertificate(files, pass);
    } catch (error) {
      const text = message(error);
      if (!(asksToConfirm(text) && window.confirm(text))) return setUpres({ text });
      try {
        await api.installHttpsCertificate(files, pass, true);
      } catch (again) {
        return setUpres({ text: message(again) });
      }
    }
    toast.success("Certificate in use.");
    setUpres(null);
    setPass("");
    if (filesRef.current) filesRef.current.value = "";
    await load();
  }

  async function previous() {
    try {
      await api.restorePreviousHttpsCertificate();
    } catch (error) {
      return setErr(message(error));
    }
    await load();
  }

  async function downloadRequest() {
    const blob = await api.downloadHttpsRequest();
    const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "hawk-ai.csr" });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
  }

  async function createRequest(event: FormEvent) {
    event.preventDefault();
    try {
      await api.createHttpsRequest(splitNames(csrNames), csrOrg);
      await downloadRequest();
      await load();
    } catch (error) {
      setErr(message(error));
    }
  }

  async function selfSigned() {
    try {
      await api.makeSelfSignedCertificate(splitNames(csrNames));
      toast.success("Self-signed certificate made.");
      await load();
    } catch (error) {
      setErr(message(error));
    }
  }

  async function letsEncrypt(event: FormEvent) {
    event.preventDefault();
    try {
      await api.startLetsEncrypt({ names: splitNames(le.names), email: le.email, agree: le.agree, staging: le.staging });
      toast.success("Asking Let’s Encrypt: this takes under a minute.");
      setTimeout(() => load().catch(() => undefined), 4000);
    } catch (error) {
      setErr(message(error));
    }
  }

  const cert = h?.certificate ?? null;
  const sum = cert?.summary;
  const issues = certificateIssues(cert);
  const chip = h ? certificateChip(h) : null;
  const acme = h?.acme;
  const uploadIssues = upres?.report ? certificateIssues(upres.report) : [];

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-https">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">HTTPS</h1>
            <span className="crumbs">for the whole of Hawk AI · Owners and admins only</span>
          </div>
        </div>
        <div id="tab">
          {loadError ? (
            <div className="panel">
              <div className="err">{loadError}</div>
            </div>
          ) : null}
          {!h && !loadError ? <p className="muted">Loading…</p> : null}
          {h && hard && acme ? (
            <div className="grid g2">
              <div className="panel">
                <h2>
                  How the server is reached{" "}
                  <span className={`chip ${modeChip(h.mode)}`}>
                    <i />
                    {MODE_LABELS[h.mode]}
                  </span>
                </h2>
                <p className="muted small">
                  HTTPS answers on port {h.viewing.httpsPort} and plain http on port {h.viewing.httpRedirectPort} (redirected to HTTPS while HTTPS only). You are viewing this page over{" "}
                  <b>{h.viewing.secure ? "HTTPS" : "plain http"}</b>.
                </p>
                <div className="seg">
                  {MODES.map((m) => (
                    <button key={m} type="button" className={h.mode === m ? "primary" : ""} data-mode={m} onClick={() => switchMode(m)}>
                      {MODE_LABELS[m]}
                    </button>
                  ))}
                </div>
                {h.mode !== "https" ? (
                  <p className="small mt">
                    To switch to HTTPS only, open <a href={`${h.viewing.httpsUrl}/settings/https`}>{h.viewing.httpsUrl}</a> and switch there: that proves HTTPS works from your browser first.
                  </p>
                ) : null}
                <h3 className="mt">Hardening</h3>
                <form className="form" id="hard" onSubmit={(event) => event.preventDefault()}>
                  <div className="row">
                    <label className="f">
                      Lowest TLS version
                      <select name="minVersion" value={hard.minVersion} onChange={(event) => saveHardening({ ...hard, minVersion: event.target.value })}>
                        {["TLSv1.2", "TLSv1.3"].map((v) => (
                          <option key={v}>{v}</option>
                        ))}
                      </select>
                    </label>
                    <label className="f">
                      HSTS for
                      <select name="maxAge" value={hard.maxAge} onChange={(event) => saveHardening({ ...hard, maxAge: Number(event.target.value) })}>
                        {h.hstsAges.map((a) => (
                          <option key={a} value={a}>
                            {hstsAgeLabel(a)}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <label className="check">
                    <input type="checkbox" name="hsts" checked={hard.hsts} onChange={(event) => saveHardening({ ...hard, hsts: event.target.checked })} />
                    <span>
                      HSTS: browsers refuse plain http to this name<small>Only with HTTPS only and a certificate browsers trust.</small>
                    </span>
                  </label>
                  <label className="check">
                    <input type="checkbox" name="sub" checked={hard.sub} onChange={(event) => saveHardening({ ...hard, sub: event.target.checked })} />
                    <span>Include subdomains</span>
                  </label>
                </form>
                <div className={`saved-foot ${hardSaved.bad ? "bad" : ""}`} id="hardsaved" role="status" aria-live="polite">
                  {hardSaved.text}
                </div>
                <div className="err" id="herr" role="alert">
                  {err}
                </div>
              </div>

              <div className="panel">
                <h2>
                  Certificate in use{" "}
                  {chip ? (
                    <span className={`chip ${chip.kind}`}>
                      <i />
                      {chip.text}
                    </span>
                  ) : null}
                </h2>
                {sum?.subject ? (
                  <dl className="kv">
                    <dt>For</dt>
                    <dd>{sum.subject}</dd>
                    <dt>Names</dt>
                    <dd className="mono small">{(sum.names ?? []).join(", ")}</dd>
                    <dt>Issuer</dt>
                    <dd>{sum.issuer ?? ""}</dd>
                    <dt>Valid until</dt>
                    <dd>
                      {date(sum.validTo)}
                      {sum.daysLeft !== undefined ? ` · ${sum.daysLeft} days` : ""}
                    </dd>
                    <dt>Source</dt>
                    <dd>{sourceLabel(h)}</dd>
                  </dl>
                ) : (
                  <p className="muted">No certificate in use (HTTP only).</p>
                )}
                {issues.length ? (
                  <div className="callout warn mt">
                    {issues.map((issue) => (
                      <div key={issue}>{issue}</div>
                    ))}
                  </div>
                ) : null}
                <h3 className="mt">Upload your certificate</h3>
                <form className="form" id="up" onSubmit={install}>
                  <label className="f">
                    Certificate files <span className="muted">PEM (certificate, chain and key, in any files) or one .pfx</span>
                    <input ref={filesRef} type="file" name="files" multiple accept=".pem,.crt,.cer,.key,.pfx,.p12" />
                  </label>
                  <label className="f">
                    Key or .pfx passphrase <span className="muted">if any</span>
                    <input type="password" name="pass" autoComplete="off" value={pass} onChange={(event) => setPass(event.target.value)} />
                  </label>
                  <div className="flex">
                    <button type="button" id="inspect" onClick={inspect}>
                      Check it
                    </button>
                    <button className="primary" type="submit">
                      Check and put to use
                    </button>
                    {h.previous ? (
                      <button type="button" className="ghost" id="prev" onClick={previous}>
                        Put the previous one back
                      </button>
                    ) : null}
                  </div>
                  <div id="upres" className="small mt">
                    {upres?.text ?? null}
                    {upres?.report ? (
                      <>
                        {upres.report.summary?.subject ? (
                          <>
                            <b>{upres.report.summary.subject}</b> · valid until {date(upres.report.summary.validTo)} · {(upres.report.summary.names ?? []).join(", ")}
                          </>
                        ) : null}
                        {uploadIssues.length ? (
                          <div className="callout warn mt">
                            {uploadIssues.map((issue) => (
                              <div key={issue}>{issue}</div>
                            ))}
                          </div>
                        ) : (
                          <div className="ok-t">Checked like a browser would: it works.</div>
                        )}
                      </>
                    ) : null}
                  </div>
                </form>
                <details className="mt">
                  <summary>No certificate yet? Ask IT with a request (CSR), or use a self-signed one</summary>
                  <form className="form mt" id="csr" onSubmit={createRequest}>
                    <label className="f">
                      Names it is for
                      <input name="names" value={csrNames} onChange={(event) => setCsrNames(event.target.value)} />
                    </label>
                    <label className="f">
                      Organisation
                      <input name="org" value={csrOrg} onChange={(event) => setCsrOrg(event.target.value)} />
                    </label>
                    <div className="flex">
                      <button type="submit">Create a request</button>
                      {h.request?.available ? (
                        <button type="button" className="ghost" id="csrdl" onClick={() => downloadRequest().catch((error) => setErr(message(error)))}>
                          <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M12 3v12m0 0-4-4m4 4 4-4M5 21h14" />
                          </svg>
                          Download the request
                        </button>
                      ) : null}
                      <button type="button" className="ghost" id="ss" onClick={selfSigned}>
                        Make a self-signed one for these names
                      </button>
                    </div>
                  </form>
                </details>
              </div>

              <div className="panel">
                <h2>
                  Free certificate from Let&apos;s Encrypt{" "}
                  {acme.issued ? (
                    <span className="chip ok">
                      <i />
                      {acme.issued.names?.join(", ")} · renews by itself
                    </span>
                  ) : null}
                </h2>
                <p className="muted small">
                  For a public name the internet reaches on port 80. Renewed 30 days before it expires.
                  {acme.fromEnvironment ? ` Set by LETSENCRYPT_DOMAIN: ${acme.fromEnvironment}.` : ""}
                </p>
                <form className="form" id="le" onSubmit={letsEncrypt}>
                  <div className="row">
                    <label className="f">
                      Names
                      <input name="names" value={le.names} onChange={(event) => setLe({ ...le, names: event.target.value })} />
                    </label>
                    <label className="f">
                      Email for expiry notices
                      <input name="email" type="email" value={le.email} onChange={(event) => setLe({ ...le, email: event.target.value })} />
                    </label>
                  </div>
                  <label className="check">
                    <input type="checkbox" name="agree" checked={le.agree} onChange={(event) => setLe({ ...le, agree: event.target.checked })} />
                    <span>
                      I accept the{" "}
                      <a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener noreferrer">
                        Let&apos;s Encrypt Subscriber Agreement
                      </a>
                    </span>
                  </label>
                  <label className="check">
                    <input type="checkbox" name="staging" checked={le.staging} onChange={(event) => setLe({ ...le, staging: event.target.checked })} />
                    <span>Staging (a test certificate browsers do not trust)</span>
                  </label>
                  <div className="flex">
                    <button className="primary" type="submit">
                      Get the certificate
                    </button>
                    {acme.issued ? (
                      <>
                        <button
                          type="button"
                          id="renew"
                          onClick={() => api.renewLetsEncrypt().then(() => toast.success("Renewing."), (error) => setErr(message(error)))}
                        >
                          Renew now
                        </button>
                        <button
                          type="button"
                          className="ghost"
                          id="leoff"
                          onClick={() => api.stopLetsEncrypt().then(() => load(), (error) => setErr(message(error)))}
                        >
                          Stop renewing
                        </button>
                      </>
                    ) : null}
                  </div>
                  {acme.running || acme.last ? <p className="small mt">{acmeLine(acme, dateTime)}</p> : null}
                </form>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
