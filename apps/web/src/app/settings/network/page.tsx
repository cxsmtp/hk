"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import { certificateFileData, networkAdvice, proxyNow, STEP_NAMES, TRUST_SOURCES, WINDOWS_EXPORT } from "@/lib/records";
import type { NetworkInfo, NetworkResult, TrustDiagnosis, TrustedCertificate } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const date = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");

function Steps({ results }: { results: NetworkResult[] }) {
  if (!results.length) return null;
  return (
    <ol className="net-steps" id="network-steps">
      {results.map((r) => (
        <li key={`${r.host}:${r.port}`}>
          <b className="mono">{r.host}</b>
          <ul>
            {r.steps.map((s, i) => (
              <li key={`${s.step}-${i}`} className={s.ok ? "ok" : "bad"}>
                <span className="net-mark" aria-hidden="true">
                  {s.ok ? "✓" : "✕"}
                </span>{" "}
                <span className="net-name">{STEP_NAMES[s.step] ?? s.step}</span> {s.detail}
                {s.ok ? null : <div className="muted small">{networkAdvice(s)}</div>}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}

/** A certificate a server presented that is not trusted here (CxMissionZero's certificateCard): the root a company
 * proxy presents, to trust with one click, and in every case an upload, which keeps only what this connection needs. */
function CertificateCard({ found, onTrusted }: { found: TrustDiagnosis; onTrusted: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [say, setSay] = useState("");
  const c = found.candidate;

  async function trust() {
    if (!c) return;
    setSay("Trusting…");
    try {
      await api.trustPresented(found.host, found.port, c.fingerprint256);
      setSay(`Trusted. ${found.host} is reached with it now.`);
      onTrusted();
    } catch (error) {
      setSay(message(error));
    }
  }

  async function upload(file: File | undefined) {
    if (!file) return;
    setSay("Reading the certificate…");
    try {
      const done = await api.uploadCertificate(await certificateFileData(file), found.host, found.port);
      setSay(done.added.length ? `Trusted ${done.added.map((a) => a.subject).join(", ")}.${done.trusted === false ? ` ${found.host} is still not trusted.` : ""}` : "Already trusted.");
      onTrusted();
    } catch (error) {
      setSay(message(error));
    }
  }

  return (
    <div className="cert-card">
      {found.status === "other" ? (
        <p className="small">
          {found.host}&apos;s certificate is not a trust question ({found.error}): it may have expired, or not name this address.
        </p>
      ) : null}
      {found.status === "needs-upload" ? (
        <p className="small">
          {found.host}&apos;s certificate is issued by &quot;{found.issuer}&quot;{found.vendor ? ` (${found.vendor})` : ""}, which is not trusted here, and its root could not be found. Upload your company&apos;s root certificate.
        </p>
      ) : null}
      {c ? (
        <dl className="kv">
          <dt>Certificate</dt>
          <dd className="mono">
            {c.subject}
            {c.organization && c.organization !== c.subject ? ` · ${c.organization}` : ""}
          </dd>
          {c.vendor ? (
            <>
              <dt>Product</dt>
              <dd>{c.vendor}</dd>
            </>
          ) : null}
          <dt>Valid until</dt>
          <dd>{date(c.validTo)}</dd>
          <dt>SHA-256 fingerprint</dt>
          <dd className="mono cert-fp">{c.fingerprint256}</dd>
        </dl>
      ) : null}
      <div className="flex mt">
        {c ? (
          <button type="button" className="primary" onClick={trust}>
            Trust and connect
          </button>
        ) : null}
        <button type="button" className={c ? "link" : "primary"} onClick={() => fileRef.current?.click()}>
          Upload a certificate…
        </button>
        <input ref={fileRef} type="file" accept=".pem,.crt,.cer,.der,.txt" hidden onChange={(event) => upload(event.target.files?.[0])} />
      </div>
      <details className="mt">
        <summary>Export the certificates from Windows</summary>
        <p className="muted small">On a Windows computer on your company network, paste this into the command prompt (cmd). It saves company-certificates.pem on the desktop: upload that file here.</p>
        <pre className="code">{WINDOWS_EXPORT}</pre>
        <button type="button" className="link" onClick={() => navigator.clipboard.writeText(WINDOWS_EXPORT).then(() => toast.success("Copied."), () => toast.error("Copying is blocked here."))}>
          Copy the command
        </button>
      </details>
      <p className="small" role="status">
        {say}
      </p>
    </div>
  );
}

/**
 * Settings → Network & proxy: CxMissionZero's page (public/index.html #set-network, public/app/system.js, docs/network.md)
 * in FTR Command Center's settings look. How Hawk AI reaches the services its connectors use: directly, or through the
 * company proxy (checked step by step, saved only when it lets the service through); what the network team needs to
 * allow; and the certificates outgoing connections trust (a company proxy's root, or an intermediate a server left out).
 * Owners and admins only; it applies to the whole installation.
 */
export default function NetworkSettingsPage() {
  const [info, setInfo] = useState<NetworkInfo | null>(null);
  const [certs, setCerts] = useState<TrustedCertificate[]>([]);
  const [loadError, setLoadError] = useState("");
  const [form, setForm] = useState({ url: "", target: "", username: "", password: "", noProxy: "" });
  const [status, setStatus] = useState<{ text: string; bad: boolean }>({ text: "", bad: false });
  const [results, setResults] = useState<NetworkResult[]>([]);
  const [found, setFound] = useState<TrustDiagnosis | null>(null);
  const [copyStatus, setCopyStatus] = useState("");
  const [trustStatus, setTrustStatus] = useState("");
  const trustFile = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    try {
      const [network, trusted] = await Promise.all([api.getNetwork(), api.getTrusted()]);
      setInfo(network);
      setCerts(trusted.certificates);
      if (network.proxy?.source === "settings") setForm((f) => ({ ...f, url: network.proxy?.url ?? "", username: network.proxy?.username ?? "", noProxy: network.proxy?.noProxy ?? "" }));
      setLoadError("");
    } catch (error) {
      setLoadError(message(error));
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  /** After a check, a certificate step that failed: what that server presents, and what to do (CxMissionZero's card). */
  async function lookAtCertificate(list: NetworkResult[]) {
    const bad = list.find((r) => r.steps.some((s) => s.step === "certificate" && !s.ok));
    setFound(null);
    if (!bad) return;
    try {
      const diagnosis = await api.diagnoseCertificate(bad.host, bad.port);
      if (diagnosis.status === "repaired") toast.success(`${bad.host} left out its intermediate certificate: it was fetched and is trusted now.`);
      if (diagnosis.status !== "trusted" && diagnosis.status !== "repaired") setFound(diagnosis);
      await load();
    } catch {
      // The steps already say what failed.
    }
  }

  async function check() {
    setStatus({ text: form.url.trim() ? "Checking through the proxy…" : "Checking the direct connection…", bad: false });
    try {
      const done = await api.checkNetwork(form);
      setResults(done.results);
      setStatus({ text: done.ok ? "The service can be reached this way." : "The service could not be reached this way: see the steps below.", bad: !done.ok });
      await lookAtCertificate(done.results);
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setStatus({ text: "Checking through the proxy before saving…", bad: false });
    try {
      const done = await api.saveNetwork(form);
      setResults(done.results);
      setForm((f) => ({ ...f, password: "" }));
      setInfo(done);
      setStatus({ text: `Saved. Restart Hawk AI to use the proxy everywhere: ${done.restart}.`, bad: false });
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    }
  }

  async function remove() {
    if (!window.confirm("Stop using the proxy? Hawk AI then connects directly, which works only if your network allows it.")) return;
    try {
      const done = await api.removeNetwork();
      setForm({ url: "", target: form.target, username: "", password: "", noProxy: "" });
      setInfo(done);
      setStatus({ text: `Removed. Restart Hawk AI to connect directly: ${done.restart}.`, bad: false });
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(info?.text ?? "");
      setCopyStatus("Copied.");
    } catch {
      setCopyStatus("Copying is blocked here: use Download.");
    }
  }

  function download() {
    const url = URL.createObjectURL(new Blob([info?.text ?? ""], { type: "text/plain;charset=utf-8" }));
    const link = Object.assign(document.createElement("a"), { href: url, download: "hawk-ai-network-requirements.txt" });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  async function removeTrusted(fp: string) {
    if (!window.confirm("Stop trusting this certificate? Connections that need it stop working until it is trusted again.")) return;
    try {
      setCerts((await api.removeTrusted(fp)).certificates);
      setTrustStatus("Removed.");
    } catch (error) {
      setTrustStatus(message(error));
    }
  }

  async function uploadTrusted(file: File | undefined) {
    if (!file) return;
    setTrustStatus("Reading the certificate…");
    try {
      const done = await api.uploadCertificate(await certificateFileData(file));
      setCerts(done.certificates);
      setTrustStatus(done.added.length ? `Trusted ${done.added.map((a) => a.subject).join(", ")}.` : "Already trusted.");
    } catch (error) {
      setTrustStatus(message(error));
    }
    if (trustFile.current) trustFile.current.value = "";
  }

  const set = (key: keyof typeof form) => (event: { target: { value: string } }) => setForm((f) => ({ ...f, [key]: event.target.value }));

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-network">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Network &amp; proxy</h1>
            <span className="crumbs">for the whole of Hawk AI · Owners and admins only</span>
          </div>
        </div>
        {loadError ? (
          <div className="panel">
            <div className="empty">
              <b>{loadError}</b>
            </div>
          </div>
        ) : null}
        {!info && !loadError ? <p className="muted">Loading…</p> : null}
        {info ? (
          <div className="grid">
            <div className="panel" id="set-network">
              <h2>Network &amp; proxy</h2>
              <p className="muted small">How Hawk AI reaches the services its connectors use: directly, or through your company&apos;s proxy. Everything it sends is encrypted (HTTPS). Leave the proxy empty to connect directly.</p>
              <div className="guard-line" id="network-now">
                {proxyNow(info)}
              </div>
              <form className="form" id="network-form" autoComplete="off" onSubmit={save}>
                <div className="row">
                  <label className="f">
                    Proxy server
                    <input id="network-url" placeholder="proxy.acme.local:8080" spellCheck={false} value={form.url} onChange={set("url")} />
                  </label>
                  <label className="f">
                    Service address to check
                    <input id="network-target" placeholder={info.targets[0]?.host ?? "graph.microsoft.com"} spellCheck={false} value={form.target} onChange={set("target")} />
                  </label>
                </div>
                <div className="row">
                  <label className="f">
                    User name, if the proxy asks for one
                    <input id="network-user" autoComplete="off" spellCheck={false} value={form.username} onChange={set("username")} />
                  </label>
                  <label className="f">
                    Password
                    <input id="network-password" type="password" autoComplete="new-password" placeholder={info.proxy?.hasPassword ? "Saved: leave blank to keep it" : ""} value={form.password} onChange={set("password")} />
                  </label>
                </div>
                <label className="f">
                  Hosts that skip the proxy (comma-separated)
                  <input id="network-noproxy" placeholder=".acme.local, smtp.acme.local, 10.0.0.5" spellCheck={false} value={form.noProxy} onChange={set("noProxy")} />
                </label>
                <p className="muted small">Windows sign-in to the proxy (NTLM/Kerberos) is not supported: ask for this server to be allowed by its IP address, or for a user name and password. Email (SMTP) always goes directly.</p>
                <div className="flex">
                  <button type="button" id="network-check" className="ghost" onClick={check}>
                    Check the connection
                  </button>
                  <button type="submit" className="primary">
                    Save
                  </button>
                  {info.proxy?.source === "settings" ? (
                    <button type="button" id="network-remove" className="link" onClick={remove}>
                      Stop using the proxy
                    </button>
                  ) : null}
                  <span className={`small ${status.bad ? "err" : "ok-t"}`} id="network-status" role="status">
                    {status.text}
                  </span>
                </div>
              </form>
              <Steps results={results} />
              {found ? <CertificateCard found={found} onTrusted={() => load().then(() => setFound(null))} /> : null}
              <p className="muted small mt">
                A saved proxy is used from the next start of the API, the worker and the scheduler: <span className="mono">{info.restart}</span>. A trusted certificate is used at once.
              </p>

              <h3>What your network team needs to allow</h3>
              <p className="muted small">Worked out from this server&apos;s settings and the connectors set up. Send it to your network team before you install, or when a connection is blocked.</p>
              <div className="tw">
                <table>
                  <thead>
                    <tr>
                      <th>Direction</th>
                      <th>What</th>
                      <th>Host</th>
                      <th>Port</th>
                      <th>Route</th>
                    </tr>
                  </thead>
                  <tbody id="network-rows">
                    {info.requirements.map((r, i) => (
                      <tr key={`${r.what}-${r.host}-${i}`} title={r.why}>
                        <td>{r.direction === "In" ? "Incoming" : "Outgoing"}</td>
                        <td>{r.what}</td>
                        <td className="mono small">{r.host}</td>
                        <td>{r.port}</td>
                        <td className="small">{r.route}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex mt">
                <button type="button" id="network-copy" className="ghost" onClick={copy}>
                  Copy for your network team
                </button>
                <button type="button" id="network-download" className="link" onClick={download}>
                  Download (.txt)
                </button>
                <span className="small muted" id="network-copy-status">
                  {copyStatus}
                </span>
              </div>
            </div>

            <div className="panel" id="trust-panel">
              <h2>
                Trusted certificates <small>{certs.length ? `(${certs.length})` : ""}</small>
              </h2>
              <p className="muted small">Certificate authorities Hawk AI trusts for its own connections (connectors, single sign-on, email) besides the public ones: your company proxy&apos;s root, or an intermediate a server left out. Used at once, with no restart.</p>
              <ul className="trust-list" id="trust-list">
                {certs.length ? (
                  certs.map((c) => (
                    <li key={c.fingerprint256}>
                      <div>
                        <b className="mono">{c.subject}</b>
                        {c.vendor ? <span className="chip"> {c.vendor}</span> : null}
                        {c.expired ? (
                          <span className="chip warn">
                            <i />
                            Expired
                          </span>
                        ) : null}
                      </div>
                      <div className="muted small">
                        {TRUST_SOURCES[c.source] ?? c.source}
                        {c.host ? ` · ${c.host}` : ""} · {date(c.addedAt)}
                        {c.addedBy ? ` · ${c.addedBy}` : ""} · valid until {date(c.validTo)}
                      </div>
                      <div className="muted mono cert-fp">{c.fingerprint256}</div>
                      <button type="button" className="link" onClick={() => removeTrusted(c.fingerprint256)}>
                        Remove
                      </button>
                    </li>
                  ))
                ) : (
                  <li className="muted small">None: only the public certificate authorities are trusted.</li>
                )}
              </ul>
              <div className="flex">
                <button type="button" className="link" id="trust-pick" onClick={() => trustFile.current?.click()}>
                  Upload a certificate…
                </button>
                <input ref={trustFile} type="file" id="trust-file" accept=".pem,.crt,.cer,.der,.txt" hidden onChange={(event) => uploadTrusted(event.target.files?.[0])} />
                <span className="small muted" id="trust-status" role="status">
                  {trustStatus}
                </span>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </AppShell>
  );
}
