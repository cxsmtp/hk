"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { LICENCE_CHANGED_EVENT, licenceBannerText } from "@/lib/licence";
import type { AdminLicence } from "@/lib/licence";

/**
 * The 3-day trial, or a licence's last 30 days (/settings/guide/licence): owners and admins are told, with the end
 * and the time left, at the top of every page, until a .hawkai licence moves it (Settings → Licence).
 */
export function LicenceBanner() {
  const [licence, setLicence] = useState<AdminLicence | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then((me) => {
        if (!cancelled) setLicence(me?.licence ?? null);
      })
      .catch(() => undefined);
    const changed = (event: Event) => {
      const detail = (event as CustomEvent<AdminLicence | null>).detail;
      if (detail) setLicence(detail);
    };
    window.addEventListener(LICENCE_CHANGED_EVENT, changed);
    return () => {
      cancelled = true;
      window.removeEventListener(LICENCE_CHANGED_EVENT, changed);
    };
  }, []);

  const text = licenceBannerText(licence);
  if (!text) return null;
  return (
    <div role="status" data-ui="licence-banner" className="border-b border-amber-900/60 bg-amber-950/40 px-4 py-2 text-[13px] leading-5 text-amber-200 sm:px-6 sm:py-2.5 sm:text-sm">
      {text}
    </div>
  );
}
