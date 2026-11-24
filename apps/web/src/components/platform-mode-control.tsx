"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { getSession } from "@/lib/auth";
import type { PlatformMode } from "@/lib/types";

function boundedError(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error || "Request failed");
  try {
    const parsed = JSON.parse(raw) as { detail?: string };
    if (parsed.detail) return String(parsed.detail).slice(0, 240);
  } catch {
    // The API client may return plain text rather than JSON.
  }
  return raw.trim().slice(0, 240) || "Request failed";
}

export function PlatformModeControl({ compact = false }: { compact?: boolean } = {}) {
  const [confirmedMode, setConfirmedMode] = useState<PlatformMode | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmingEnforce, setConfirmingEnforce] = useState(false);

  const role = String(getSession()?.userRole || "").trim().toLowerCase();
  const canManage = ["owner", "admin"].includes(role);

  const refreshConfirmedMode = useCallback(async () => {
    try {
      const response = await api.getPlatformMode();
      setConfirmedMode(response.platform_mode);
      setError(null);
    } catch (requestError) {
      setError(`Mode could not be confirmed: ${boundedError(requestError)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshConfirmedMode().catch(() => undefined);
    window.addEventListener("focus", refreshConfirmedMode);
    return () => window.removeEventListener("focus", refreshConfirmedMode);
  }, [refreshConfirmedMode]);

  const applyMode = useCallback(async (targetMode: PlatformMode) => {
    if (saving || targetMode === confirmedMode) return;
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updatePlatformMode(targetMode);
      setConfirmedMode(updated.platform_mode);
      setConfirmingEnforce(false);
      try {
        const refreshed = await api.getPlatformMode();
        setConfirmedMode(refreshed.platform_mode);
      } catch (revalidationError) {
        const modeLabel = updated.platform_mode === "enforce" ? "Enforce" : "Monitor";
        setError(
          `Mode changed to ${modeLabel}, but revalidation is temporarily unavailable: ${boundedError(revalidationError)}`,
        );
      }
    } catch (requestError) {
      setError(`Mode change failed: ${boundedError(requestError)}`);
    } finally {
      setSaving(false);
    }
  }, [confirmedMode, saving]);

  const requestMode = useCallback((targetMode: PlatformMode) => {
    if (!canManage || saving || loading || confirmedMode === null || targetMode === confirmedMode) return;
    if (targetMode === "enforce") {
      setConfirmingEnforce(true);
      return;
    }
    setConfirmingEnforce(false);
    applyMode(targetMode).catch(() => undefined);
  }, [applyMode, canManage, confirmedMode, loading, saving]);

  const status = useMemo(() => {
    if (loading) return { label: "Checking", tone: "border-slate-700 bg-slate-900 text-slate-300" };
    if (confirmedMode === "enforce") {
      return { label: "Enforce", tone: "border-orange-500/50 bg-orange-500/10 text-orange-200" };
    }
    if (confirmedMode === "discovery") {
      return { label: "Monitor", tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" };
    }
    return { label: "Unavailable", tone: "border-rose-500/40 bg-rose-500/10 text-rose-200" };
  }, [confirmedMode, loading]);

  const controlsDisabled = loading || saving || confirmedMode === null || !canManage;

  if (compact) {
    return (
      <section aria-label="Platform operating mode" className="rounded-xl border border-[#2b3448] bg-[#0c1018] px-4 py-3 shadow-[0_12px_36px_rgba(0,0,0,0.2)]">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1.5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-brand-300">Tenant mode</p>
            <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${status.tone}`}>{status.label}</span>
            <p className="text-[10px] text-slate-500">Applies only to verified inline paths; it does not prove endpoint acknowledgement.</p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <Button type="button" size="sm" variant={confirmedMode === "discovery" ? "default" : "outline"} aria-pressed={confirmedMode === "discovery"} disabled={controlsDisabled || confirmedMode === "discovery"} onClick={() => requestMode("discovery")}>
              {saving && confirmedMode === "enforce" ? "Returning…" : "Monitor"}
            </Button>
            <Button type="button" size="sm" variant={confirmedMode === "enforce" ? "default" : "outline"} aria-pressed={confirmedMode === "enforce"} disabled={controlsDisabled || confirmedMode === "enforce"} onClick={() => requestMode("enforce")} className={confirmedMode === "enforce" ? "bg-orange-400 hover:bg-orange-300" : "border-orange-500/40 text-orange-200 hover:bg-orange-500/10"}>
              {saving && confirmedMode !== "enforce" ? "Activating…" : "Enforce"}
            </Button>
            <Button asChild variant="ghost" size="sm"><Link href="/interaction-security">View decision evidence</Link></Button>
          </div>
        </div>
        {!canManage && !loading ? <p className="mt-2 text-[10px] text-slate-600">Owner or administrator access is required to change platform mode.</p> : null}
        {error ? <div role="alert" className="mt-2 rounded-md border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-xs text-rose-200">{error}</div> : null}
        {confirmingEnforce ? (
          <div className="mt-3 flex flex-col justify-between gap-3 border-t border-orange-500/25 pt-3 lg:flex-row lg:items-center">
            <p className="text-xs text-orange-100"><span className="font-semibold">Confirm Enforce for the entire tenant.</span> Bypassed paths remain Not Covered.</p>
            <div className="flex shrink-0 gap-2">
              <Button type="button" variant="ghost" size="sm" disabled={saving} onClick={() => setConfirmingEnforce(false)}>Cancel</Button>
              <Button type="button" size="sm" disabled={saving} onClick={() => applyMode("enforce").catch(() => undefined)} className="bg-orange-400 text-black hover:bg-orange-300">{saving ? "Activating…" : "Confirm Enforce"}</Button>
            </div>
          </div>
        ) : null}
      </section>
    );
  }

  return (
    <section
      aria-labelledby="platform-mode-heading"
      className="relative overflow-hidden rounded-xl border border-[#2b3448] bg-[#0c1018] shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
    >
      <div className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-brand-400 via-orange-400 to-emerald-400" />
      <div className="grid gap-5 px-5 py-5 lg:grid-cols-[minmax(0,1.3fr)_minmax(310px,0.7fr)] lg:items-center lg:px-6">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-brand-300">Tenant control authority</p>
            <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${status.tone}`}>
              {status.label}
            </span>
          </div>
          <h2 id="platform-mode-heading" className="mt-2 text-xl font-semibold tracking-tight text-slate-50">
            Platform operating mode
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Monitor records would-decisions without claiming prevention. Enforce activates policy outcomes only on verified inline Browser, Gateway, MCP, SDK, Foundry, and Endpoint paths.
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant={confirmedMode === "discovery" ? "default" : "outline"}
              aria-pressed={confirmedMode === "discovery"}
              disabled={controlsDisabled || confirmedMode === "discovery"}
              onClick={() => requestMode("discovery")}
            >
              {saving && confirmedMode === "enforce" ? "Returning to Monitor…" : "Monitor"}
            </Button>
            <Button
              type="button"
              variant={confirmedMode === "enforce" ? "default" : "outline"}
              aria-pressed={confirmedMode === "enforce"}
              disabled={controlsDisabled || confirmedMode === "enforce"}
              onClick={() => requestMode("enforce")}
              className={confirmedMode === "enforce" ? "bg-orange-400 hover:bg-orange-300" : "border-orange-500/40 text-orange-200 hover:bg-orange-500/10"}
            >
              {saving && confirmedMode !== "enforce" ? "Activating…" : "Enforce"}
            </Button>
            <Button asChild variant="ghost" size="sm">
              <Link href="/interaction-security">View decision evidence</Link>
            </Button>
          </div>
          {!canManage && !loading ? (
            <p className="mt-3 text-xs text-slate-500">Owner or administrator access is required to change platform mode.</p>
          ) : null}
          {error ? (
            <div role="alert" className="mt-3 rounded-md border border-rose-900/60 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">
              {error}
            </div>
          ) : null}
        </div>

        <div className="rounded-lg border border-[#252d3e] bg-[#10151f] px-4 py-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">Activation truth</p>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            The badge is the confirmed tenant setting. Endpoint agents apply it on their next authenticated policy refresh; this setting alone does not prove endpoint acknowledgement.
          </p>
          <div className="mt-3 flex items-center justify-between border-t border-[#252d3e] pt-3 text-xs">
            <span className="text-slate-500">Scope</span>
            <span className="font-semibold text-slate-200">Entire tenant</span>
          </div>
        </div>
      </div>

      {confirmingEnforce ? (
        <div className="border-t border-orange-500/30 bg-orange-950/20 px-5 py-4 lg:px-6">
          <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
            <div>
              <p className="font-semibold text-orange-100">Confirm Enforce for the entire tenant</p>
              <p className="mt-1 text-sm text-orange-200/70">
                Verified inline Browser, Gateway, MCP, SDK, Foundry, and Endpoint requests will apply block, redact, warn, scope, and approval decisions. Bypassed paths remain Not Covered.
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              <Button type="button" variant="ghost" disabled={saving} onClick={() => setConfirmingEnforce(false)}>
                Cancel
              </Button>
              <Button
                type="button"
                disabled={saving}
                onClick={() => applyMode("enforce").catch(() => undefined)}
                className="bg-orange-400 text-black hover:bg-orange-300"
              >
                {saving ? "Activating…" : "Confirm Enforce"}
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
