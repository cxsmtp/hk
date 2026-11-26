"use client";

import "@/styles/ftr.css";

import { FormEvent, useCallback, useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { RecoveryCodes, TwoStepKey } from "@/components/two-step-key";
import { api } from "@/lib/api";
import { refusalFrom } from "@/lib/sign-in";
import type { TwoStepSetup, TwoStepState } from "@/lib/sign-in";

type Step = "idle" | "setup" | "off" | "codes";

/**
 * Settings → Two-step sign-in, for oneself (/settings/guide/people-and-access): CxMissionZero's Your profile → Two-step sign-in (its
 * wording and steps), in FTR Command Center's profile look (ftr-cc-dashboard public/js/profile.js: head compact, one
 * panel, h3 sections). Turning it on asks for a first code from the app; turning it off or making new recovery codes
 * asks for a current code from the app (a recovery code is not enough).
 */
export default function TwoStepPage() {
  const [state, setState] = useState<TwoStepState | null>(null);
  const [step, setStep] = useState<Step>("idle");
  const [setup, setSetup] = useState<TwoStepSetup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<{ text: string; bad: boolean }>({ text: "", bad: false });
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const me = await api.me();
      setState(me.two_step ?? null);
    } catch (error) {
      setStatus({ text: refusalFrom(error instanceof Error ? error.message : "").message, bad: true });
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  async function start() {
    setStatus({ text: "", bad: false });
    try {
      setSetup(await api.twoStepSetup());
      setStep("setup");
      setCode("");
    } catch (error) {
      setStatus({ text: refusalFrom(error instanceof Error ? error.message : "").message, bad: true });
    }
  }

  async function confirm(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setStatus({ text: "", bad: false });
    try {
      const typed = code.trim();
      const result = step === "setup" ? await api.twoStepEnable(typed) : step === "off" ? await api.twoStepDisable(typed) : await api.twoStepRecoveryCodes(typed);
      setState(result.two_step);
      setCode("");
      const fresh = (result as { recovery_codes?: string[] }).recovery_codes;
      if (fresh) {
        setCodes(fresh);
      } else {
        setStatus({ text: "Two-step sign-in is off.", bad: false });
      }
      setSetup(null);
      setStep("idle");
    } catch (error) {
      const refusal = refusalFrom(error instanceof Error ? error.message : "");
      setStatus({ text: refusal.message, bad: true });
      if (refusal.restart) {
        setSetup(null);
        setStep("idle");
      }
    } finally {
      setBusy(false);
    }
  }

  const ask =
    step === "setup"
      ? "Enter the six-digit code the app shows. Only then is two-step sign-in on."
      : step === "off"
        ? "To turn two-step sign-in off, enter a current code from your authenticator app."
        : "To make new recovery codes, enter a current code from your authenticator app. The old ones stop working.";

  return (
    <AppShell>
      <div className="ftr" data-ui="settings-two-step">
        <div className="head compact">
          <div className="ht">
            <h1>Two-step sign-in</h1>
            <span className="crumbs">a code from your phone after your password · only you can change it</span>
          </div>
        </div>
        <div className="panel">
          <p className="muted small">
            After your password, a six-digit code from an authenticator app on your phone: someone who learns your password still cannot sign in as you. It is asked for when you sign in with your password, not when you sign in with single sign-on.
          </p>
          {state ? (
            <dl className="kv">
              <dt>Two-step sign-in</dt>
              <dd>
                {state.on ? (
                  <span className="chip ok">
                    <i />
                    On{state.since ? ` since ${new Date(state.since).toLocaleDateString()}` : ""}
                  </span>
                ) : (
                  <span className="chip">
                    <i />
                    Off
                  </span>
                )}
              </dd>
              {state.on ? (
                <>
                  <dt>Recovery codes left</dt>
                  <dd>{state.recoveryLeft}</dd>
                </>
              ) : null}
              {state.required ? (
                <>
                  <dt>Required</dt>
                  <dd>An administrator requires it for everyone who signs in with a password.</dd>
                </>
              ) : null}
            </dl>
          ) : null}

          {codes ? (
            <>
              <div className="sep-line" />
              <h3>Recovery codes</h3>
              <p className="muted small">
                If you lose your phone, one of these recovery codes signs you in instead of a code from the app. Each works once. They are shown only now: keep them somewhere safe, not on the phone itself.
              </p>
              <RecoveryCodes codes={codes} />
              <div className="flex mt">
                <button type="button" className="primary" onClick={() => setCodes(null)}>
                  I have saved them
                </button>
              </div>
            </>
          ) : null}

          {state && !codes && step === "idle" ? (
            <div className="flex mt">
              {!state.on ? (
                <button type="button" className="primary" onClick={start} disabled={!state.available}>
                  Turn on two-step sign-in
                </button>
              ) : (
                <>
                  <button type="button" onClick={() => { setStep("codes"); setCode(""); setStatus({ text: "", bad: false }); }}>
                    New recovery codes
                  </button>
                  {!state.required ? (
                    <button type="button" className="ghost" onClick={() => { setStep("off"); setCode(""); setStatus({ text: "", bad: false }); }}>
                      Turn off two-step sign-in
                    </button>
                  ) : null}
                </>
              )}
            </div>
          ) : null}
          {state && !state.available ? <p className="small muted mt">Two-step sign-in is for people who sign in with a password.</p> : null}

          {step === "setup" && setup ? (
            <>
              <div className="sep-line" />
              <ol className="twostep-steps">
                <li>Install an authenticator app on your phone, if you have none: Microsoft Authenticator, Google Authenticator, or any other that makes six-digit codes.</li>
                <li>In the app, add an account and scan this QR code. If you cannot scan it, type the key instead.</li>
                <li>Enter the six-digit code the app shows. Only then is two-step sign-in on.</li>
              </ol>
              <TwoStepKey setup={setup} />
            </>
          ) : null}

          {step !== "idle" ? (
            <form className="form mt" onSubmit={confirm} autoComplete="off">
              <p className="muted small">{ask}</p>
              <label className="f">
                Code from your authenticator app
                <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={20} spellCheck={false} required autoFocus />
              </label>
              <div className="flex">
                <button type="submit" className="primary" disabled={busy}>
                  Confirm
                </button>
                <button type="button" className="ghost" onClick={() => { setStep("idle"); setSetup(null); setCode(""); }}>
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
          <p role="status" aria-live="polite" className={`small mt ${status.bad ? "err" : "muted"}`}>
            {status.text}
          </p>
        </div>
      </div>
    </AppShell>
  );
}
