"use client";

import { useEffect, useState } from "react";

import { InstallationId, LicenceRequestButton, LicenceUpload } from "@/components/licence-tools";
import { api } from "@/lib/api";
import { getSession, setSession } from "@/lib/auth";
import { activatedText, LICENCE_DEACTIVATED_EVENT } from "@/lib/licence";
import type { LicenceView } from "@/lib/licence";
import { isTwoStepChallenge, refusalFrom } from "@/lib/sign-in";
import type { TwoStepChallenge } from "@/lib/sign-in";
import type { LoginResponse } from "@/lib/types";

/**
 * The deactivation page (/settings/guide/licence): once the installation's 3-day trial is over without a licence, or
 * its licence has expired, every page shows that Hawk AI has been deactivated, with this installation's ID. An owner
 * or admin of the server signs in here (the API lets sign-in and the licence routes through) to download the
 * licence request and upload the .hawkai licence; the page then reloads and everything works again as it was.
 */
export function LicenceGate({ children }: { children: React.ReactNode }) {
  const [deactivated, setDeactivated] = useState(false);
  const [installationId, setInstallationId] = useState("");

  useEffect(() => {
    const show = () => setDeactivated(true);
    window.addEventListener(LICENCE_DEACTIVATED_EVENT, show);
    // The licence itself is open to everyone: ask once when the page loads, signed in or not.
    api
      .getLicence()
      .then((licence) => {
        if (licence?.installationId) setInstallationId(licence.installationId);
        if (licence && licence.active === false) setDeactivated(true);
      })
      .catch(() => undefined);
    return () => window.removeEventListener(LICENCE_DEACTIVATED_EVENT, show);
  }, []);

  if (!deactivated) return <>{children}</>;
  return <DeactivatedScreen installationId={installationId} />;
}

type Phase = "checking" | "signin" | "twostep" | "ready" | "not-admin";

const field = "mt-1 w-full min-w-0 rounded-lg border border-white/[0.1] bg-[#07090d] px-3 py-2 text-sm text-slate-100";

function DeactivatedScreen({ installationId }: { installationId: string }) {
  const [phase, setPhase] = useState<Phase>("checking");
  const [view, setView] = useState<LicenceView | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState<TwoStepChallenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; kind: "" | "ok" | "error" }>({ text: "", kind: "" });

  /** The licence's status for the person signed in, trying each workspace they administer: the server's first. */
  async function openFor(tenants: Array<{ id: string; role: string }>, preferred?: string): Promise<void> {
    const admin = tenants.filter((t) => t.role === "owner" || t.role === "admin");
    const ordered = [...admin.filter((t) => t.id === preferred), ...admin.filter((t) => t.id !== preferred)];
    for (const tenant of ordered) {
      const current = getSession();
      if (current) setSession({ ...current, tenantId: tenant.id, userRole: tenant.role });
      try {
        const status = await api.getLicenceStatus();
        if (status.canManage) {
          setView(status);
          setPhase("ready");
          return;
        }
      } catch {
        // Not this workspace: the next one.
      }
    }
    setPhase("not-admin");
  }

  useEffect(() => {
    // Already signed in (the licence ended while the console was open): straight to the upload.
    if (!getSession()) {
      setPhase("signin");
      return;
    }
    api
      .getLicenceStatus()
      .then((status) => {
        setView(status);
        setPhase(status.canManage ? "ready" : "not-admin");
      })
      .catch(() => setPhase("signin"));
  }, []);

  async function signedIn(result: LoginResponse) {
    const tenantId = result.selected_tenant_id || result.tenants?.[0]?.id || "";
    setSession({ tenantId, userRole: result.tenants?.find((t) => t.id === tenantId)?.role, user: result.user });
    setPassword("");
    setCode("");
    await openFor(result.tenants || [], tenantId);
  }

  async function signIn(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage({ text: "", kind: "" });
    try {
      const result = await api.login(email.trim(), password);
      if (isTwoStepChallenge(result)) {
        if (result.setup) {
          setMessage({ text: "Two-step sign-in has to be set up first, and that needs Hawk AI working. Ask another administrator, or reach out to Bhawani Singh.", kind: "error" });
          return;
        }
        setChallenge(result);
        setPhase("twostep");
        return;
      }
      await signedIn(result);
    } catch (error) {
      setMessage({ text: refusalFrom(error instanceof Error ? error.message : "", "Sign-in failed.").message, kind: "error" });
    } finally {
      setBusy(false);
    }
  }

  async function secondStep(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!challenge) return;
    setBusy(true);
    setMessage({ text: "", kind: "" });
    try {
      const result = await api.twoStep(challenge.ticket, code.trim());
      setChallenge(null);
      await signedIn(result);
    } catch (error) {
      const refusal = refusalFrom(error instanceof Error ? error.message : "");
      setMessage({ text: refusal.message, kind: "error" });
      if (refusal.restart) {
        setChallenge(null);
        setPhase("signin");
      }
    } finally {
      setBusy(false);
    }
  }

  const shownId = view?.installationId || installationId;

  return (
    <div data-ui="licence-deactivated" className="grid min-h-screen place-items-center overflow-x-hidden bg-[#07090d] px-4 py-6 text-slate-100">
      <main className="w-full min-w-0 max-w-[560px] rounded-2xl border border-white/[0.08] bg-[#0a0f16] px-5 py-6 shadow-2xl sm:px-6 sm:py-7">
        <div className="mb-4 text-sm font-semibold text-slate-400">Hawk AI</div>
        <h1 className="mb-2 text-xl font-semibold">The product has been deactivated.</h1>
        <p className="mb-3.5 text-sm">
          Please reach out to <strong>Bhawani Singh</strong>.
        </p>
        <p className="mb-4 text-[13.5px] text-slate-400">
          This installation&apos;s trial or licence has ended. Nothing has been deleted: your settings, history and data are kept, and everything works again as soon as a
          licence for this installation is uploaded.
        </p>
        <InstallationId id={shownId} />

        <section className="mt-5 border-t border-white/[0.08] pt-4">
          <h2 className="text-sm font-semibold">Upload a licence</h2>
          {phase === "checking" ? <p className="mt-2 text-sm text-slate-400">Checking…</p> : null}

          {phase === "signin" ? (
            <form onSubmit={signIn} className="mt-2 space-y-3" data-ui="licence-signin">
              <p className="text-[13px] text-slate-400">An owner or admin of this server signs in to download the licence request and upload the .hawkai licence.</p>
              <label className="block text-xs text-slate-400" htmlFor="licence-email">
                Email
                <input id="licence-email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className={field} />
              </label>
              <label className="block text-xs text-slate-400" htmlFor="licence-password">
                Password
                <input id="licence-password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} className={field} />
              </label>
              <button type="submit" disabled={busy} className="min-h-[38px] rounded-lg bg-brand-500 px-4 text-sm font-semibold text-black disabled:opacity-60">
                Sign in
              </button>
            </form>
          ) : null}

          {phase === "twostep" ? (
            <form onSubmit={secondStep} className="mt-2 space-y-3">
              <label className="block text-xs text-slate-400" htmlFor="licence-two-step">
                The code from your authenticator app, or a recovery code
                <input id="licence-two-step" inputMode="numeric" autoComplete="one-time-code" maxLength={20} spellCheck={false} required value={code} onChange={(e) => setCode(e.target.value)} className={field} />
              </label>
              <button type="submit" disabled={busy} className="min-h-[38px] rounded-lg bg-brand-500 px-4 text-sm font-semibold text-black disabled:opacity-60">
                Continue
              </button>
            </form>
          ) : null}

          {phase === "not-admin" ? (
            <p className="mt-2 text-sm text-slate-400">Only an owner or admin of this server&apos;s first workspace can upload a licence. Ask one of them, or reach out to Bhawani Singh.</p>
          ) : null}

          {phase === "ready" && view ? (
            <div className="mt-3 space-y-4">
              <LicenceRequestButton installationId={view.installationId} />
              <LicenceUpload
                onImported={(result) => {
                  setMessage({ text: activatedText(result.product.until), kind: "ok" });
                  setTimeout(() => window.location.reload(), 1200);
                }}
              />
            </div>
          ) : null}

          <p
            role="status"
            aria-live="polite"
            className={`mt-2.5 min-h-5 break-words text-[13.5px] ${message.kind === "error" ? "text-red-400" : message.kind === "ok" ? "text-emerald-400" : ""}`}
          >
            {message.text}
          </p>
        </section>
      </main>
    </div>
  );
}
