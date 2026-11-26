"use client";

import { useCallback, useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import {
  errorMessageFrom,
  historyLine,
  LICENCE_CHANGED_EVENT,
  productStatusLine,
  tenantsStatusLine,
} from "@/lib/licence";
import type { ActivationView } from "@/lib/licence";

/**
 * Settings → Activation codes (/settings/guide/licence), ported from CxMissionZero's Settings → Activation codes:
 * the product licence (until when Hawk AI works), the tenants code, the last codes entered, and a field to apply a
 * code from the maintainer. Owners and admins only.
 */
export default function ActivationCodesPage() {
  const [view, setView] = useState<ActivationView | null>(null);
  const [loadError, setLoadError] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<{ text: string; kind: "ok" | "error" | "" }>({ text: "", kind: "" });

  const load = useCallback(async () => {
    try {
      setView(await api.getActivation());
      setLoadError("");
    } catch (error) {
      setLoadError(errorMessageFrom(error instanceof Error ? error.message : "", "Activation codes are unavailable."));
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  async function apply() {
    const trimmed = code.trim();
    if (!trimmed) {
      setStatus({ text: "Paste the activation code first.", kind: "error" });
      return;
    }
    setBusy(true);
    try {
      const result = await api.applyActivation(trimmed);
      setView(result);
      setCode("");
      setStatus({ text: `Applied: ${result.applied}.`, kind: "ok" });
      // A product code moves the licence's end: the banner follows.
      window.dispatchEvent(new CustomEvent(LICENCE_CHANGED_EVENT, { detail: result.product }));
    } catch (error) {
      setStatus({ text: errorMessageFrom(error instanceof Error ? error.message : ""), kind: "error" });
    } finally {
      setBusy(false);
    }
  }

  const product = view?.product;
  const tenants = view?.tenants;

  return (
    <AppShell>
      <div className="space-y-5">
        <PageHeader
          eyebrow="Administration"
          title="Activation codes"
          description="Some add-ons are unlocked with a code from the maintainer of Hawk AI. Paste the code you were sent: it is checked here, with nothing sent anywhere, and what it unlocks is switched on at once."
        />
        <PageSection title="In force">
          {loadError ? <p className="text-sm text-red-400">{loadError}</p> : null}
          {!view && !loadError ? <p className="text-sm text-slate-500">Loading…</p> : null}
          {product ? (
            <ul className="space-y-2 text-sm text-slate-200">
              <li data-ui="licence-product">
                <strong>{productStatusLine(product)}</strong>
                {product.warn ? <span className="ml-2 font-semibold text-amber-300">{product.daysLeft} days left</span> : null}
              </li>
              {tenants ? (
                <li data-ui="licence-tenants">
                  {tenantsStatusLine(tenants)}
                  {tenants.warn ? <span className="ml-2 font-semibold text-amber-300">{tenants.daysLeft} days left</span> : null}
                </li>
              ) : (
                <li className="text-slate-500">No add-ons are unlocked yet. Without a tenants code Hawk AI serves 1 tenant.</li>
              )}
            </ul>
          ) : null}
          {view && !view.keyConfigured ? <p className="mt-3 text-xs text-slate-500">This build has no maintainer key, so no code can be checked.</p> : null}
        </PageSection>
        <PageSection title="Apply a code">
          <label className="block text-xs text-slate-400" htmlFor="activation-code">
            Activation code
          </label>
          <textarea
            id="activation-code"
            rows={3}
            spellCheck={false}
            autoComplete="off"
            placeholder="HK1.…"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            className="mt-1.5 w-full break-all rounded-lg border border-white/[0.1] bg-[#07090d] px-3 py-2 font-mono text-xs text-slate-100"
          />
          <div className="mt-3 flex items-center gap-3">
            <Button type="button" onClick={apply} disabled={busy}>
              Apply the code
            </Button>
            <span role="status" aria-live="polite" className={`text-sm ${status.kind === "error" ? "text-red-400" : status.kind === "ok" ? "text-emerald-400" : ""}`}>
              {status.text}
            </span>
          </div>
        </PageSection>
        <PageSection title="Codes entered" description="The last 10 codes applied here or on the deactivation page.">
          {view?.history.length ? (
            <ul className="space-y-1.5 text-xs text-slate-300">
              {view.history.map((entry, index) => (
                <li key={`${entry.id}-${entry.at}-${index}`}>{historyLine(entry)}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">No code has been entered yet.</p>
          )}
        </PageSection>
      </div>
    </AppShell>
  );
}
