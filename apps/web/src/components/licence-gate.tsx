"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { activatedText, errorMessageFrom, LICENCE_DEACTIVATED_EVENT } from "@/lib/licence";

/**
 * The deactivation page (/settings/guide/licence), ported from CxMissionZero's public/deactivated.html: once the
 * product licence has ended, every page shows that Hawk AI has been deactivated, with a field for the activation
 * code from the maintainer. On success the page reloads and everything works again as it was.
 */
export function LicenceGate({ children }: { children: React.ReactNode }) {
  const [deactivated, setDeactivated] = useState(false);

  useEffect(() => {
    const show = () => setDeactivated(true);
    window.addEventListener(LICENCE_DEACTIVATED_EVENT, show);
    // The licence itself is open to everyone: ask once when the page loads, signed in or not.
    api
      .getLicence()
      .then((licence) => {
        if (licence && licence.active === false) setDeactivated(true);
      })
      .catch(() => undefined);
    return () => window.removeEventListener(LICENCE_DEACTIVATED_EVENT, show);
  }, []);

  if (!deactivated) return <>{children}</>;
  return <DeactivatedScreen />;
}

function DeactivatedScreen() {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<{ text: string; kind: "" | "ok" | "error" }>({ text: "", kind: "" });

  async function activate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setStatus({ text: "Checking the code…", kind: "" });
    try {
      const result = await api.activateLicence(code);
      setStatus({ text: activatedText(result.until), kind: "ok" });
      setTimeout(() => window.location.reload(), 1200);
    } catch (error) {
      setStatus({ text: errorMessageFrom(error instanceof Error ? error.message : ""), kind: "error" });
      setBusy(false);
    }
  }

  return (
    <div data-ui="licence-deactivated" className="grid min-h-screen place-items-center bg-[#07090d] px-4 py-6 text-slate-100">
      <main className="w-full max-w-[520px] rounded-2xl border border-white/[0.08] bg-[#0a0f16] px-6 py-7 shadow-2xl">
        <div className="mb-4 text-sm font-semibold text-slate-400">Hawk AI</div>
        <h1 className="mb-2 text-xl font-semibold">The product has been deactivated.</h1>
        <p className="mb-3.5 text-sm">
          Please reach out to <strong>Bhawani Singh</strong>.
        </p>
        <p className="mb-3.5 text-[13.5px] text-slate-400">
          Nothing has been deleted: your settings, history and data are kept, and everything works again as soon as an activation code is entered.
        </p>
        <details className="mt-4 border-t border-white/[0.08] pt-3.5">
          <summary className="cursor-pointer text-sm font-semibold">Enter an activation code</summary>
          <form onSubmit={activate} autoComplete="off">
            <label htmlFor="licence-code" className="mb-1.5 mt-3 block text-[13px] text-slate-400">
              Activation code
            </label>
            <textarea
              id="licence-code"
              name="code"
              spellCheck={false}
              placeholder="HK1.…"
              required
              value={code}
              onChange={(event) => setCode(event.target.value)}
              className="min-h-24 w-full resize-y break-all rounded-lg border border-white/[0.1] bg-[#07090d] px-3 py-2.5 font-mono text-xs text-slate-100"
            />
            <button
              type="submit"
              disabled={busy}
              className="mt-2.5 min-h-[38px] rounded-lg bg-brand-500 px-4 text-sm font-semibold text-black disabled:opacity-60"
            >
              Activate
            </button>
            <p
              role="status"
              aria-live="polite"
              className={`mt-2.5 min-h-5 text-[13.5px] ${status.kind === "error" ? "text-red-400" : status.kind === "ok" ? "text-emerald-400" : ""}`}
            >
              {status.text}
            </p>
          </form>
        </details>
      </main>
    </div>
  );
}
