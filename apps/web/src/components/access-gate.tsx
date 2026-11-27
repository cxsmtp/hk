"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api, signOut as endSession } from "@/lib/api";
import { getSession, SESSION_CHANGE_EVENT } from "@/lib/auth";
import {
  accessNeededFor,
  newPasswordProblem,
  PASSWORD_CHANGE_EVENT,
  TERMS_REQUIRED_EVENT,
  termsFormProblem,
  termsHtml,
  termsStep,
} from "@/lib/access";
import type { AccessNeeded, TermsState, TermsView } from "@/lib/access";
import { errorMessageFrom } from "@/lib/licence";

/**
 * First sign-in (/settings/guide/install), ported from CxMissionZero's public/app/session.js: someone with a temporary
 * password chooses their own first, then the terms are accepted (every owner or admin accepts the licence agreement for
 * the organisation, with the company name, their name and email; everyone else the terms of use for users,
 * once that is done). Until then the API answers 403 (apps/api/app/core/access_gate.py) and this shows the page instead.
 */
export function AccessGate({ children }: { children: React.ReactNode }) {
  const [needed, setNeeded] = useState<AccessNeeded>(null);
  const [terms, setTerms] = useState<TermsState | null>(null);
  const [email, setEmail] = useState("");

  const check = useCallback(() => {
    const session = getSession();
    if (!session?.tenantId) {
      setNeeded(null);
      return;
    }
    setEmail(session.user?.email || "");
    api
      .me()
      .then((me) => {
        setTerms(me?.terms ?? null);
        setNeeded(accessNeededFor(me));
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const passwordFirst = () => setNeeded("password");
    const termsFirst = () => {
      setNeeded((current) => (current === "password" ? current : "terms"));
      check();
    };
    check();
    window.addEventListener(PASSWORD_CHANGE_EVENT, passwordFirst);
    window.addEventListener(TERMS_REQUIRED_EVENT, termsFirst);
    window.addEventListener(SESSION_CHANGE_EVENT, check);
    return () => {
      window.removeEventListener(PASSWORD_CHANGE_EVENT, passwordFirst);
      window.removeEventListener(TERMS_REQUIRED_EVENT, termsFirst);
      window.removeEventListener(SESSION_CHANGE_EVENT, check);
    };
  }, [check]);

  if (needed === "password") return <ChangePasswordScreen email={email} onDone={check} />;
  if (needed === "terms") return <TermsScreen state={terms} onDone={() => window.location.reload()} />;
  return <>{children}</>;
}

function signOut() {
  void endSession().finally(() => window.location.assign("/login"));
}

function Screen({ children, wide = false }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <div data-ui="access-gate" className="hawk-signin grid min-h-screen place-items-center bg-[#07090d] px-3 py-6 text-slate-100 sm:px-4">
      <main className={`w-full ${wide ? "max-w-[760px]" : "max-w-[520px]"} rounded-2xl border border-white/[0.08] bg-[#0a0f16] px-5 py-6 shadow-2xl sm:px-7 sm:py-7`}>
        <div className="mb-4 text-sm font-semibold text-slate-400">Hawk AI</div>
        {children}
      </main>
    </div>
  );
}

const fieldClass = "w-full rounded-lg border border-white/[0.1] bg-[#07090d] px-3 py-2.5 text-sm text-slate-100";
const labelClass = "mb-1.5 mt-3 block text-[13px] text-slate-400";
const primaryClass = "min-h-[38px] rounded-lg bg-brand-500 px-4 text-sm font-semibold text-black disabled:opacity-60";
const ghostClass = "min-h-[38px] rounded-lg border border-white/[0.1] px-4 text-sm text-slate-300";

function ChangePasswordScreen({ email, onDone }: { email: string; onDone: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const problem = newPasswordProblem(current, next, repeat);
    if (problem) {
      setStatus(problem);
      return;
    }
    setBusy(true);
    setStatus("");
    try {
      // The new tokens come back as cookies (everyone else signed in as this person is signed out).
      await api.changePassword(current, next);
      onDone();
    } catch (error) {
      setStatus(errorMessageFrom(error instanceof Error ? error.message : "", "The password could not be changed."));
      setBusy(false);
    }
  }

  return (
    <Screen>
      <h1 className="mb-2 text-xl font-semibold">Choose a new password</h1>
      <p className="mb-1 text-sm text-slate-400">An administrator set a temporary password for you. Choose your own to continue.</p>
      {email ? <p className="text-sm text-slate-300">{email}</p> : null}
      <form onSubmit={save} autoComplete="off">
        <label htmlFor="change-current" className={labelClass}>
          Current password
        </label>
        <input id="change-current" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} className={fieldClass} required />
        <label htmlFor="change-next" className={labelClass}>
          New password (12+ characters)
        </label>
        <input id="change-next" type="password" autoComplete="new-password" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} className={fieldClass} required />
        <label htmlFor="change-next2" className={labelClass}>
          Confirm
        </label>
        <input id="change-next2" type="password" autoComplete="new-password" minLength={12} value={repeat} onChange={(e) => setRepeat(e.target.value)} className={fieldClass} required />
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button type="submit" disabled={busy} className={primaryClass}>
            Save password
          </button>
          <button type="button" onClick={signOut} className={ghostClass}>
            Sign out
          </button>
        </div>
        <p role="status" aria-live="polite" className="mt-2.5 min-h-5 text-[13.5px] text-red-400">
          {status}
        </p>
      </form>
    </Screen>
  );
}

function TermsScreen({ state, onDone }: { state: TermsState | null; onDone: () => void }) {
  const [view, setView] = useState<TermsView | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const [read, setRead] = useState(false);
  const [companyName, setCompanyName] = useState("");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [authorised, setAuthorised] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const textRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api
      .getTerms()
      .then((terms) => {
        setView(terms);
        setCompanyName(terms.organisationName || "");
        setFullName(terms.you?.fullName || "");
        setEmail(terms.you?.email || "");
      })
      .catch(() => setLoadFailed(true));
  }, []);

  const onScroll = useCallback(() => {
    const text = textRef.current;
    if (text && text.scrollTop + text.clientHeight >= text.scrollHeight - 24) setReadToEnd(true);
  }, []);

  useEffect(() => {
    // Short enough to need no scrolling.
    if (view) requestAnimationFrame(onScroll);
  }, [view, onScroll]);

  const step = termsStep(state ?? { organisationAccepted: false, canAcceptForOrganisation: false });
  const forOrganisation = step === "organisation";
  const problem = forOrganisation ? termsFormProblem({ read, companyName, fullName, email, authorised }) : read ? "" : "Tick that you have read the terms.";
  const shown = view ? (forOrganisation || step === "wait" ? view.text : view.userText || view.text) : "";

  async function accept() {
    if (!view) return;
    if (problem) {
      setStatus(problem);
      return;
    }
    setBusy(true);
    setStatus("");
    try {
      await api.acceptTerms(
        forOrganisation
          ? { version: view.version, hash: view.hash, read, forOrganisation: true, companyName: companyName.trim(), fullName: fullName.trim(), email: email.trim(), authorised }
          : { version: view.version, hash: view.hash, read },
      );
      onDone();
    } catch (error) {
      setStatus(errorMessageFrom(error instanceof Error ? error.message : "", "The terms could not be accepted."));
      setBusy(false);
    }
  }

  async function checkAgain() {
    try {
      const me = await api.me();
      if (me?.terms?.organisationAccepted) onDone();
      else setStatus("Not accepted yet.");
    } catch (error) {
      setStatus(errorMessageFrom(error instanceof Error ? error.message : "", "Not accepted yet."));
    }
  }

  const organisation = view?.organisation;
  return (
    <Screen wide>
      <p data-ui="onprem-note" className="mb-3 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-3 py-2.5 text-[13px] text-emerald-300">
        <b>On premise, your data stays yours.</b> {view?.notice}
      </p>
      <h1 className="mb-1 text-xl font-semibold">
        {forOrganisation ? "Licence agreement" : "Terms of use"}
        {view ? ` · version ${view.version}` : ""}
      </h1>
      <p className="mb-3 text-[13px] text-slate-400">
        {forOrganisation
          ? "Hawk AI is licensed, not sold. Accept the End User Licence Agreement for your company to continue; a copy is emailed to you, now or as soon as the mail server is set up."
          : "Your organisation has accepted Hawk AI's licence agreement (Settings → About). Accept the terms of use for users to continue."}
        {organisation ? ` Accepted for the organisation by ${organisation.by} on ${new Date(organisation.at).toLocaleDateString()}.` : ""}
      </p>
      <div
        ref={textRef}
        onScroll={onScroll}
        tabIndex={0}
        translate="no"
        className="terms-text max-h-[45vh] overflow-y-auto rounded-lg border border-white/[0.08] bg-[#07090d] px-4 py-3 text-[13.5px] leading-relaxed text-slate-200 [&_h3]:mb-1.5 [&_h3]:mt-4 [&_h3]:font-semibold [&_li]:ml-5 [&_li]:list-disc [&_p]:mb-2"
        dangerouslySetInnerHTML={{ __html: view ? termsHtml(shown) : loadFailed ? "<p>The terms could not be loaded. Reload the page.</p>" : "<p>Loading…</p>" }}
      />
      {view ? <p className="mt-1.5 break-all text-[11.5px] text-slate-500">SHA-256 {view.hash}</p> : null}
      {step === "wait" ? (
        <p className="mt-3 text-sm text-amber-300">
          An administrator must accept the licence agreement for your organisation before Hawk AI can be used. Ask them to sign in, then try again.
        </p>
      ) : (
        <>
          {!readToEnd ? <p className="mt-3 text-[13px] text-slate-400">Read to the end to accept.</p> : null}
          <label className="mt-3 flex items-start gap-2 text-sm">
            <input id="terms-read" type="checkbox" disabled={!readToEnd} checked={read} onChange={(e) => setRead(e.target.checked)} className="mt-1" />
            <span>{forOrganisation ? "I have read the whole licence agreement, including its limits of liability." : "I have read these terms of use and accept them."}</span>
          </label>
          {forOrganisation ? (
            <div data-ui="terms-acceptor" className="mt-1 grid gap-x-3 sm:grid-cols-3">
              <div>
                <label htmlFor="terms-company" className={labelClass}>
                  Company (legal name)
                </label>
                <input id="terms-company" maxLength={120} autoComplete="organization" placeholder="Acme Corporation LLC" value={companyName} onChange={(e) => setCompanyName(e.target.value)} className={fieldClass} required />
              </div>
              <div>
                <label htmlFor="terms-name" className={labelClass}>
                  Your full name
                </label>
                <input id="terms-name" maxLength={200} autoComplete="name" value={fullName} onChange={(e) => setFullName(e.target.value)} className={fieldClass} required />
              </div>
              <div>
                <label htmlFor="terms-email" className={labelClass}>
                  Your email (the copy goes here)
                </label>
                <input id="terms-email" type="email" maxLength={254} autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} className={fieldClass} required />
              </div>
            </div>
          ) : null}
          {forOrganisation ? (
            <label className="mt-3 flex items-start gap-2 text-sm">
              <input id="terms-authorised" type="checkbox" checked={authorised} onChange={(e) => setAuthorised(e.target.checked)} className="mt-1" />
              <span>I accept this agreement on behalf of the company named above and confirm that I am authorised to bind it. Until it is accepted, nobody can use Hawk AI.</span>
            </label>
          ) : null}
        </>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {step === "wait" ? (
          <button type="button" onClick={checkAgain} className={primaryClass}>
            Check again
          </button>
        ) : (
          <button type="button" disabled={busy || !view || !read} onClick={accept} className={primaryClass}>
            Accept and continue
          </button>
        )}
        <button type="button" onClick={signOut} className={ghostClass}>
          Decline and sign out
        </button>
      </div>
      <p role="status" aria-live="polite" className="mt-2.5 min-h-5 text-[13.5px] text-red-400">
        {status}
      </p>
    </Screen>
  );
}
