"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { integrityNoticeText } from "@/lib/updates-settings";
import type { IntegrityState } from "@/lib/updates-settings";

/** Sent by Settings → Updates when a check changes what owners and admins are told. */
export const INTEGRITY_NOTICE_CHANGED_EVENT = "hawk:integrity-notice-changed";

type Notice = { state: IntegrityState; summary: string } | null;

/**
 * Software integrity (/settings/guide/updates): while the running files differ from what the release workflow built, or their
 * list is not signed by it, owners and admins are told at the top of every page, as CxMissionZero alerts them when
 * they sign in. Everyone else is told nothing (the API answers them with no notice).
 */
export function IntegrityNotice() {
  const [notice, setNotice] = useState<Notice>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getIntegrityNotice()
      .then((answer) => {
        if (!cancelled) setNotice(answer?.notice ?? null);
      })
      .catch(() => undefined);
    const changed = (event: Event) => setNotice(((event as CustomEvent<Notice>).detail ?? null) as Notice);
    window.addEventListener(INTEGRITY_NOTICE_CHANGED_EVENT, changed);
    return () => {
      cancelled = true;
      window.removeEventListener(INTEGRITY_NOTICE_CHANGED_EVENT, changed);
    };
  }, []);

  const text = integrityNoticeText(notice);
  if (!text) return null;
  return (
    <div role="alert" data-ui="integrity-notice" className="border-b border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-200 sm:px-6">
      {text}{" "}
      <a href="/settings/updates" className="font-medium underline">
        Settings → Updates
      </a>
    </div>
  );
}
