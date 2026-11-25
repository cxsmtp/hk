"use client";

import "../ftr-settings.css";

import Link from "next/link";
import { useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import type { GeneralView } from "@/lib/settings-console";
import type { PlatformMode } from "@/lib/types";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const savedAt = () => `Saved ✓ ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;

/**
 * Settings → General, laid out and worded as FTR Command Center's (public/js/settings.js `general()`): one panel,
 * "Hosts & features", saved as it changes, a value the server refuses going back to the last one saved; what the
 * server was started with is shown "(set by …)" and cannot be changed here. Hawk's feature is its platform mode
 * (Monitor or Enforce); its hosts are the address people use and the names it answers to.
 */
export default function GeneralSettingsPage() {
  const [view, setView] = useState<GeneralView | null>(null);
  const [mode, setMode] = useState<PlatformMode | null>(null);
  const [saved, setSaved] = useState("Saved as you change it.");
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    Promise.all([api.getGeneralSettings(), api.getPlatformMode()])
      .then(([general, platform]) => {
        setView(general);
        setMode(platform.platform_mode);
      })
      .catch((failure) => setLoadError(message(failure)));
  }, []);

  async function saveMode(enforce: boolean) {
    const wanted: PlatformMode = enforce ? "enforce" : "discovery";
    if (enforce && !window.confirm("Enforce policies? From now on the policies block, mask and ask for approval where they say so, for everyone in this organisation.")) return;
    try {
      const answer = await api.updatePlatformMode(wanted);
      setMode(answer.platform_mode);
      setError("");
      setSaved(savedAt());
    } catch (failure) {
      setError(`${message(failure)} Back to what was saved.`);
    }
  }

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-general">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">General</h1>
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
          {view ? (
            <div className="panel">
              <h2>
                Hosts &amp; features <small>The name, logo and look are under Branding</small>
              </h2>
              <form className="form" id="sf" onSubmit={(event) => event.preventDefault()}>
                <label className="check">
                  <input type="checkbox" name="enforce" checked={mode === "enforce"} onChange={(event) => saveMode(event.target.checked)} />
                  <span>
                    Enforce policies <span className="chip warn">off by default</span>
                    <small>
                      Off (Monitor): Hawk AI watches, records and recommends; nothing is blocked. On: the published policies block, mask and ask for approval where they say so. For this organisation; the same switch as the one on the Overview.
                    </small>
                  </span>
                </label>
                <div className="row">
                  <label className="f">
                    Server address (set by PUBLIC_URL)
                    <input value={view.serverAddress || "PUBLIC_URL is not set"} disabled />
                  </label>
                  <label className="f">
                    Host names (set by TRUSTED_HOSTS)
                    <textarea rows={3} value={view.trustedHosts.join("\n")} disabled />
                  </label>
                </div>
                <p className="muted small">
                  The server address is where links in emails point (password resets, welcome emails, hands-off). Requests for any other host name are refused. The addresses this server goes out to, and its proxy, are under{" "}
                  <Link href="/settings/network">Network &amp; proxy</Link>.
                </p>
                <div className="flex">
                  <span className="small muted" id="ssaved">
                    {saved}
                  </span>
                  <span className="err" id="serr">
                    {error}
                  </span>
                </div>
              </form>
            </div>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
