"use client";

import { useCallback, useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { InstallationId, LicenceRequestButton, LicenceUpload } from "@/components/licence-tools";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { api } from "@/lib/api";
import {
  errorMessageFrom,
  historyLine,
  lastDayOf,
  LICENCE_CHANGED_EVENT,
  productStatusLine,
  shortDate,
  shortMoment,
  tenantsStatusLine,
  timeLeftText,
} from "@/lib/licence";
import type { LicenceImported, LicenceView } from "@/lib/licence";
import { SET_BY_SERVER } from "@/lib/settings-console";

/**
 * Settings → Licence (/settings/guide/licence): this installation's ID, its 3-day trial or the licence in force and
 * how long is left, the licence request to send to the owner of Hawk AI, the upload of the .hawkai licence they make
 * for this installation, and what was imported or refused. Owners and admins; only the server's administrators
 * import a licence.
 */
export default function LicencePage() {
  const [view, setView] = useState<LicenceView | null>(null);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      setView(await api.getLicenceStatus());
      setLoadError("");
    } catch (error) {
      setLoadError(errorMessageFrom(error instanceof Error ? error.message : "", "The licence is unavailable."));
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  function imported(result: LicenceImported) {
    setView(result);
    // The licence moves the end: the banner follows.
    window.dispatchEvent(new CustomEvent(LICENCE_CHANGED_EVENT, { detail: result.product }));
  }

  const product = view?.product;
  const licence = view?.licence;
  const tenants = view?.tenants;

  return (
    <AppShell>
      <div className="space-y-5">
        <PageHeader
          eyebrow="Administration"
          title="Licence"
          description="Each installation of Hawk AI works for 3 days from its first start. After that it needs a licence made for this installation: download the licence request, send it to Bhawani Singh, and upload the .hawkai file you receive. It is checked here, offline, with nothing sent anywhere."
        />
        <PageSection title="This installation">
          {loadError ? <p className="text-sm text-red-400">{loadError}</p> : null}
          {!view && !loadError ? <p className="text-sm text-slate-500">Loading…</p> : null}
          {view && product ? (
            <div className="space-y-4">
              <InstallationId id={view.installationId} />
              <ul className="space-y-2 text-sm text-slate-200">
                <li data-ui="licence-product" className="break-words">
                  <strong>{productStatusLine(product)}</strong>
                  {product.active ? (
                    <span className={`ml-2 font-semibold ${product.warn ? "text-amber-300" : "text-slate-400"}`}>{timeLeftText(product.hoursLeft, product.daysLeft)} left</span>
                  ) : null}
                </li>
                <li data-ui="licence-trial" className="text-slate-400">
                  Trial: {shortMoment(view.trial.start)} to {shortMoment(view.trial.end)}
                  {view.trial.active ? " (in progress)" : licence?.valid ? " (licensed)" : " (ended)"}
                </li>
                {licence ? (
                  <li data-ui="licence-holder" className="break-words">
                    Licensed to <strong>{licence.org}</strong> · {licence.valid ? `until the end of ${lastDayOf(licence.expires, "short")} (UTC)` : `expired ${shortDate(licence.expires)}`} ·{" "}
                    {licence.scopes.includes("tenants") ? "Hawk AI and several tenants" : "Hawk AI"} · licence {licence.id}
                    {licence.at ? ` · imported ${shortDate(licence.at)}${licence.by ? ` by ${licence.by}` : ""}` : ""}
                  </li>
                ) : (
                  <li className="text-slate-500">No licence has been imported on this installation.</li>
                )}
                {tenants ? (
                  <li data-ui="licence-tenants" className="break-words">
                    {tenantsStatusLine(tenants)}
                  </li>
                ) : (
                  <li className="text-slate-500">Without a licence for several tenants Hawk AI serves 1 tenant, with no cap on its users.</li>
                )}
              </ul>
              {!view.keyConfigured ? <p className="text-xs text-slate-500">This build has no owner key, so no licence can be checked.</p> : null}
            </div>
          ) : null}
        </PageSection>
        <PageSection
          title="Get and upload a licence"
          description="The request names this installation, its address, its version and your organisation; nothing secret is in it. The licence you receive works only on this installation."
        >
          {/* The licence is the whole server's: only its administrators import one. */}
          {view && view.canManage === false ? (
            <p className="text-sm text-slate-400" data-ui="server-setting-note">
              <strong>{SET_BY_SERVER}</strong> The licence applies to every workspace on this server.
            </p>
          ) : view ? (
            <div className="space-y-4">
              <LicenceRequestButton installationId={view.installationId} />
              <LicenceUpload onImported={imported} />
            </div>
          ) : null}
        </PageSection>
        <PageSection title="Licences imported and refused" description="The last 10, here or on the deactivation page.">
          {view?.history.length ? (
            <ul className="space-y-1.5 break-words text-xs text-slate-300">
              {view.history.map((entry, index) => (
                <li key={`${entry.id ?? entry.outcome}-${entry.at}-${index}`}>{historyLine(entry)}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">No licence has been imported yet.</p>
          )}
        </PageSection>
      </div>
    </AppShell>
  );
}
