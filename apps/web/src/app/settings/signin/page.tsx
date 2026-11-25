"use client";

import "@/styles/ftr.css";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { JoinSettingsPanel } from "@/components/iam/join-settings-panel";
import { api } from "@/lib/api";
import { autosave, SAVES_AS_YOU_TYPE } from "@/lib/ftr-autosave";
import { idleHours, refusalFrom, RESET_POLICY_OPTIONS } from "@/lib/sign-in";
import type { SignInPerson, SignInSettings } from "@/lib/sign-in";

/**
 * Settings → Sign-in, for owners and admins (docs/sign-in.md). The page is FTR Command Center's People → Sign-in
 * (ftr-cc-dashboard public/js/people.js `signInTab`): "Forgotten passwords" and "How people sign in", in FTR's
 * panels, wording and autosave. Two panels FTR does not have come from CxMissionZero's People & roles → Sign-in, in
 * the same look: "Two-step sign-in" (require it for everyone) and the people whose two-step sign-in or single sign-on
 * link an administrator resets; and "Email for reset links" (Hawk sends with SMTP_*; one test email marks it tested).
 */
export default function SignInSettingsPage() {
  const [view, setView] = useState<SignInSettings | null>(null);
  const [people, setPeople] = useState<SignInPerson[]>([]);
  const [loadError, setLoadError] = useState("");
  const [peopleNote, setPeopleNote] = useState("");
  const [mailNote, setMailNote] = useState<{ text: string; bad: boolean }>({ text: "", bad: false });
  const formRef = useRef<HTMLFormElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const [settings, list] = await Promise.all([api.getSignInSettings(), api.signInPeople()]);
      setView(settings);
      setPeople(list.people);
      setLoadError("");
    } catch (error) {
      setLoadError(refusalFrom(error instanceof Error ? error.message : "", "Sign-in settings are for owners and admins.").message);
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  const loaded = Boolean(view);
  useEffect(() => {
    const form = formRef.current;
    if (!form || !loaded) return;
    const saver = autosave(
      form,
      async (f) => {
        const data = new FormData(f);
        try {
          setView(await api.saveSignInSettings({ passwordReset: data.get("passwordReset"), twoStepRequired: data.get("twoStepRequired") === "on" }));
        } catch (error) {
          throw new Error(refusalFrom(error instanceof Error ? error.message : "").message);
        }
      },
      { status: statusRef.current },
    );
    return () => saver.stop();
  }, [loaded]);

  async function testEmail() {
    setMailNote({ text: "Sending…", bad: false });
    try {
      const result = await api.sendTestEmail();
      setView(result);
      setMailNote({ text: result.message, bad: false });
    } catch (error) {
      setMailNote({ text: refusalFrom(error instanceof Error ? error.message : "").message, bad: true });
    }
  }

  async function resetTwoStep(person: SignInPerson) {
    if (!window.confirm(`Reset two-step sign-in for ${person.email}? They set it up again at their next sign-in.`)) return;
    try {
      setPeople((await api.resetPersonTwoStep(person.id)).people);
      setPeopleNote(`Two-step sign-in was reset for ${person.email}.`);
    } catch (error) {
      setPeopleNote(refusalFrom(error instanceof Error ? error.message : "").message);
    }
  }

  async function resetSsoLink(person: SignInPerson) {
    if (!window.confirm(`Reset the single sign-on link of ${person.email}? Their next single sign-on links them again by their email address.`)) return;
    try {
      setPeople((await api.resetPersonSsoLink(person.id)).people);
      setPeopleNote(`The single sign-on link of ${person.email} was reset.`);
    } catch (error) {
      setPeopleNote(refusalFrom(error instanceof Error ? error.message : "").message);
    }
  }

  const ready = view?.passwordResetReady;
  return (
    <AppShell>
      <div className="ftr" data-ui="settings-signin">
        <div className="head compact">
          <div className="ht">
            <h1>Sign-in</h1>
            <span className="crumbs">how people sign in to Hawk AI · for the whole installation</span>
          </div>
        </div>
        <div className="saved-banner">{SAVES_AS_YOU_TYPE}</div>
        {loadError ? <div className="callout warn">{loadError}</div> : null}
        {!view && !loadError ? <p className="muted small">Loading…</p> : null}
        {view ? (
          <>
            <JoinSettingsPanel />
            <form className="form" ref={formRef} autoComplete="off">
              <div className="grid g2">
                <div className="panel">
                  <h2>Forgotten passwords</h2>
                  <p className="muted small">
                    &quot;Forgot your password?&quot; sends a one-time link to the account&apos;s own email. It works once, for 30 minutes, signs the account out everywhere when used, and is followed by an email saying the password was changed. The answer never says whether an address has an account.
                  </p>
                  <label className="f">
                    Who may reset a forgotten password by email
                    <select name="passwordReset" defaultValue={view.passwordReset}>
                      {RESET_POLICY_OPTIONS.map(([value, label]) => (
                        <option key={value} value={value}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </label>
                  {ready?.ready ? (
                    <div className="callout mt">&quot;Forgot your password?&quot; is working.</div>
                  ) : (
                    <div className="callout warn mt">Not available yet: {ready?.missing.join(" ")}</div>
                  )}
                  <p className="small muted mt">
                    An owner or admin who may not reset by email is given a temporary password on the server with <code>python -m app.cli.reset_admin</code>.
                  </p>
                </div>
                <div className="panel">
                  <h2>How people sign in</h2>
                  <dl className="kv">
                    <dt>Passwords</dt>
                    <dd>At least 12 characters; locked 15 minutes after 5 wrong ones.</dd>
                    <dt>Two-step sign-in</dt>
                    <dd>{view.twoStepRequired ? "Required for everyone who signs in with a password" : "Each person chooses (Settings → Two-step sign-in)"}</dd>
                    <dt>Single sign-on</dt>
                    <dd>
                      {view.sso.enabled ? `On (${view.sso.providers.map((p) => `"${p.label}"`).join(", ") || "no provider"})` : "Off"}
                      {view.sso.enabled && view.sso.passwordAdminsOnly ? "; passwords for Admins only" : ""}
                    </dd>
                    <dt>Idle sign-out</dt>
                    <dd>After {idleHours(view.sessionIdleMinutes)} hours.</dd>
                    <dt>From one address</dt>
                    <dd>At most 30 sign-in attempts in 10 minutes.</dd>
                  </dl>
                  <Link className="btn mt" href="/settings/sso">
                    Single sign-on settings
                  </Link>
                </div>
                <div className="panel wide-panel">
                  <h2>Two-step sign-in</h2>
                  <p className="muted small">
                    After the password, a six-digit code from an authenticator app on the person&apos;s phone. Each person turns it on for themselves under Settings → Two-step sign-in. It covers signing in with a password; single sign-on is not asked for a code. For the whole installation.
                  </p>
                  <label className="check">
                    <input type="checkbox" name="twoStepRequired" defaultChecked={view.twoStepRequired} />
                    <span>
                      <b>Require two-step sign-in for everyone who signs in with a password</b>
                      <small>
                        Off: each person chooses. On: a person without it sets it up at their next password sign-in, before they get in, and nobody can turn their own off. People who are signed in now carry on until they sign in again.
                      </small>
                    </span>
                  </label>
                  <p className="small muted mt">
                    Someone lost their phone and their recovery codes? Below, <b>Reset two-step</b> takes it off for them, and they set it up again. For the only owner or admin, start the API once with <code>RESET_TWO_STEP</code> set to their email address, or run <code>python -m app.cli.reset_admin</code>.
                  </p>
                </div>
              </div>
            </form>
            <div className="saved-foot" ref={statusRef}>
              All changes are saved.
            </div>
            <div className="grid g2 mt">
              <div className="panel">
                <h2>
                  Email for reset links <small>Settings → Email (SMTP)</small>
                  {view.email.tested ? (
                    <span className="chip ok">
                      <i />
                      Tested
                    </span>
                  ) : (
                    <span className="chip warn">
                      <i />
                      Not tested
                    </span>
                  )}
                </h2>
                <dl className="kv">
                  <dt>Email server</dt>
                  <dd className="mono">{view.email.host ? `${view.email.host}:${view.email.port}` : "Not set (SMTP_HOST)"}</dd>
                  <dt>From</dt>
                  <dd className="mono">{view.email.from || "Not set (SMTP_FROM)"}</dd>
                  <dt>Server address</dt>
                  <dd className="mono">{view.serverAddress || "No https address (PUBLIC_URL / WEB_ORIGIN)"}</dd>
                </dl>
                <div className="flex mt">
                  <button type="button" onClick={testEmail} disabled={!view.email.configured}>
                    Send a test email to me
                  </button>
                  <span role="status" aria-live="polite" className={`small ${mailNote.bad ? "err" : "muted"}`}>
                    {mailNote.text}
                  </span>
                </div>
                <p className="small muted mt">Reset links are sent only once a test email has arrived with exactly these settings; changing any of them asks for a new test.</p>
              </div>
              <div className="panel">
                <h2>
                  People <small>in this workspace</small>
                </h2>
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Person</th>
                      <th>Role</th>
                      <th>Two-step</th>
                      <th>Single sign-on</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {people.map((person) => (
                      <tr key={person.id}>
                        <td>
                          {person.email}
                          {person.locked ? (
                            <span className="chip bad" style={{ marginLeft: 8 }}>
                              <i />
                              Locked
                            </span>
                          ) : null}
                        </td>
                        <td>{person.role}</td>
                        <td>{person.twoStep ? "On" : "Off"}</td>
                        <td>{person.ssoLinked ? "Linked" : "—"}</td>
                        <td>
                          <div className="flex">
                            {person.twoStep && !person.you ? (
                              <button type="button" className="sm" onClick={() => resetTwoStep(person)}>
                                Reset two-step
                              </button>
                            ) : null}
                            {person.ssoLinked ? (
                              <button type="button" className="sm ghost" onClick={() => resetSsoLink(person)}>
                                Reset single sign-on link
                              </button>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {peopleNote ? <p className="small muted mt">{peopleNote}</p> : null}
              </div>
            </div>
          </>
        ) : null}
      </div>
    </AppShell>
  );
}
