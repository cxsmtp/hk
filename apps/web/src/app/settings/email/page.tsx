"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { autosave, SAVES_AS_YOU_TYPE } from "@/lib/ftr-autosave";
import { errorMessageFrom } from "@/lib/licence";
import type { SmtpSettings, SmtpView } from "@/lib/settings-console";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const dateTime = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "");

/** What the form says, as the API takes it (FTR's wireSmtp `save`). */
function smtpOf(form: HTMLFormElement): Partial<SmtpSettings> & { password?: string } {
  const f = new FormData(form);
  const smtp: Partial<SmtpSettings> & { password?: string } = {
    host: String(f.get("host") ?? ""),
    port: Number(f.get("port")),
    secure: f.get("secure") === "on",
    requireAuth: f.get("requireAuth") === "on",
    rejectUnauthorized: f.get("rejectUnauthorized") === "on",
    user: String(f.get("user") ?? ""),
    fromName: String(f.get("fromName") ?? ""),
    fromAddress: String(f.get("fromAddress") ?? ""),
  };
  if (f.get("password")) smtp.password = String(f.get("password"));
  return smtp;
}

/**
 * Settings → Email (SMTP), laid out and worded as FTR Command Center's (public/js/settings.js `email()`, `smtpPanel`,
 * `wireSmtp`): saved as typed and tested with the mail server at once, settings that fail giving way to the last ones
 * that worked; the password kept encrypted and never shown again; Test connection and Send test email. As in
 * CxMissionZero, nothing is sent until the settings in force have been tested. The one email server Hawk AI sends
 * through: sign-in links, welcome emails, support cases, hands-off, the self-check and the backups.
 */
export default function EmailSettingsPage() {
  const [view, setView] = useState<SmtpView | null>(null);
  const [loadError, setLoadError] = useState("");
  const [msg, setMsg] = useState<{ text: string; ok: boolean }>({ text: "", ok: true });
  const [to, setTo] = useState("");
  const [round, setRound] = useState(0);
  const formRef = useRef<HTMLFormElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);

  const load = useCallback(() => {
    api
      .getSmtp()
      .then((v) => {
        setView(v);
        setRound((n) => n + 1);
      })
      .catch((error) => setLoadError(message(error)));
  }, []);
  useEffect(load, [load]);

  useEffect(() => {
    const form = formRef.current;
    if (!form || !view) return;
    // Implicit TLS goes with port 465; 587 and 25 use STARTTLS.
    const port = form.elements.namedItem("port") as HTMLInputElement;
    const secure = form.elements.namedItem("secure") as HTMLInputElement;
    const onPort = () => {
      const n = Number(port.value);
      if (n === 465) secure.checked = true;
      if (n === 587 || n === 25) secure.checked = false;
    };
    port.addEventListener("change", onPort);
    // Saved as typed, and tested with the mail server at once: settings that fail give way to the last ones that worked.
    const saver = autosave(
      form,
      async (f) => {
        const smtp = smtpOf(f);
        const passwordSet = f.dataset.passwordSet === "1";
        const ready = Boolean(smtp.host && (!smtp.requireAuth || (smtp.user && (smtp.password || passwordSet))));
        const passwordReset = String(new FormData(f).get("passwordReset") ?? "");
        try {
          const next = await api.saveSmtp({ smtp, passwordReset, test: ready });
          setView(next);
          if (smtp.password) (f.elements.namedItem("password") as HTMLInputElement).value = "";
          f.dataset.passwordSet = next.smtp.passwordSet ? "1" : "";
        } catch (error) {
          // The last settings that worked are back on the server: the form shows them again.
          api.getSmtp().then(setView).catch(() => undefined);
          throw error;
        }
        return ready ? "All changes are saved ✓ and the mail server answered: email can be sent." : "All changes are saved ✓ (give the server and sign-in, and it is tested at once).";
      },
      { status: statusRef.current, delay: 1200 },
    );
    return () => {
      port.removeEventListener("change", onPort);
      saver.stop();
    };
    // Wired once per load of the settings (the form is drawn again with them).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [round]);

  async function testConnection() {
    const form = formRef.current;
    if (!form) return;
    setMsg({ text: "Saving and testing…", ok: true });
    try {
      await api.saveSmtp({ smtp: smtpOf(form), passwordReset: String(new FormData(form).get("passwordReset") ?? "") });
      const r = await api.testSmtp();
      toast.success(r.message);
      setMsg({ text: "", ok: true });
      load();
    } catch (error) {
      setMsg({ text: message(error), ok: false });
    }
  }

  async function sendTest() {
    setMsg({ text: "Sending…", ok: true });
    try {
      setMsg({ text: (await api.sendTestSmtp(to)).message, ok: true });
      load();
    } catch (error) {
      setMsg({ text: message(error), ok: false });
    }
  }

  const x = view?.smtp;
  const status = !view ? null : view.verified ? (
    <span className="chip ok">
      <i />
      Tested {dateTime(view.verifiedAt)}
    </span>
  ) : x?.host ? (
    <span className="chip warn">
      <i />
      Not tested: nothing is sent until it is
    </span>
  ) : (
    <span className="chip">
      <i />
      Not set up
    </span>
  );

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-email">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Email (SMTP)</h1>
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
          {view && x ? (
            <>
              <div className="saved-banner">{SAVES_AS_YOU_TYPE}</div>
              <div className="panel">
                <h2>
                  Email server (SMTP) {status}
                </h2>
                <p className="muted small">
                  Used for &quot;Forgot your password?&quot; links, welcome emails, support cases, hands-off and the backups. Saved as you type and tested with the mail server at once; settings that fail give way to the last ones that worked. The password is kept encrypted and never shown again.
                  {view.source === "environment" ? " Until something is saved here, the SMTP_* settings the server was started with are used." : ""}
                </p>
                <form key={round} className="form" id="smtp" ref={formRef} data-nodraft data-password-set={x.passwordSet ? "1" : ""} autoComplete="off">
                  <div className="row">
                    <label className="f">
                      Mail server
                      <input name="host" defaultValue={x.host} placeholder="smtp.office365.com" autoComplete="off" />
                    </label>
                    <label className="f">
                      Port
                      <input name="port" type="number" min={1} max={65535} defaultValue={x.port} />
                    </label>
                  </div>
                  <div className="row">
                    <label className="check">
                      <input type="checkbox" name="secure" defaultChecked={x.secure} />
                      <span>
                        Implicit TLS<small>On for port 465. Off for 587 and 25, where STARTTLS is required whenever a password is sent.</small>
                      </span>
                    </label>
                    <label className="check">
                      <input type="checkbox" name="rejectUnauthorized" defaultChecked={x.rejectUnauthorized !== false} />
                      <span>
                        Check the mail server&apos;s certificate<small>Leave on. For a private CA, trust it under Settings → Network &amp; proxy instead.</small>
                      </span>
                    </label>
                  </div>
                  <label className="check">
                    <input type="checkbox" name="requireAuth" defaultChecked={x.requireAuth} />
                    <span>The server needs a sign-in</span>
                  </label>
                  <div className="row">
                    <label className="f">
                      User name
                      <input name="user" defaultValue={x.user} autoComplete="off" />
                    </label>
                    <label className="f">
                      Password
                      <input name="password" type="password" autoComplete="new-password" placeholder={x.passwordSet ? "Kept: type to replace" : ""} />
                    </label>
                  </div>
                  <div className="row">
                    <label className="f">
                      From name
                      <input name="fromName" defaultValue={x.fromName} />
                    </label>
                    <label className="f">
                      From address
                      <input name="fromAddress" type="email" defaultValue={x.fromAddress} placeholder="Same as the user name" />
                    </label>
                  </div>
                  <div className="row">
                    <label className="f">
                      Who may reset a forgotten password by email
                      <select name="passwordReset" defaultValue={view.passwordReset}>
                        <option value="everyone">Everyone</option>
                        <option value="not-admins">Everyone but those who manage people</option>
                        <option value="off">Nobody: Admins reset passwords</option>
                      </select>
                    </label>
                    <label className="f">
                      Links in emails point at
                      <input value={view.publicUrl || "PUBLIC_URL is not set"} disabled />
                    </label>
                  </div>
                  {view.reset.ready ? (
                    <div className="callout">&quot;Forgot your password?&quot; is working.</div>
                  ) : (
                    <div className="callout warn">&quot;Forgot your password?&quot; is not available yet: {view.reset.missing.join(" ")}</div>
                  )}
                  <div className="flex">
                    <button type="button" className="primary" id="smtp-test" onClick={testConnection}>
                      Test connection
                    </button>
                    <input id="smtp-to" type="email" placeholder="Send a test to (you by default)" className="grow" value={to} onChange={(event) => setTo(event.target.value)} style={{ flex: 1, minWidth: 180 }} />
                    <button type="button" id="smtp-send" onClick={sendTest}>
                      Send test email
                    </button>
                  </div>
                  <div className={`small ${msg.ok ? "ok-t" : "err"}`} id="smtp-msg" aria-live="polite">
                    {msg.text}
                  </div>
                </form>
                <div className="saved-foot" id="smtpsaved" ref={statusRef}>
                  All changes are saved.
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
