"use client";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { backupNoticeAction, backupNoticeText } from "@/lib/backups-settings";
import type { BackupNotice as Notice } from "@/lib/backups-settings";

/** Sent by Settings → Backups & health when the notice changes (the key saved, encryption turned on). */
export const BACKUP_NOTICE_CHANGED_EVENT = "hawk:backup-notice-changed";

/**
 * Backups are encrypted with the server's own key and nobody has confirmed saving it, or backups are not encrypted
 * (docs: /settings/guide/backups): owners and admins are told at the top of every page until they act, as in
 * CxMissionZero. Everyone else is told nothing (the API answers them with no notice).
 */
export function BackupNotice() {
  const [notice, setNotice] = useState<Notice>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getBackupNotice()
      .then((answer) => {
        if (!cancelled) setNotice(answer?.notice ?? null);
      })
      .catch(() => undefined);
    const changed = (event: Event) => setNotice(((event as CustomEvent<Notice>).detail ?? null) as Notice);
    window.addEventListener(BACKUP_NOTICE_CHANGED_EVENT, changed);
    return () => {
      cancelled = true;
      window.removeEventListener(BACKUP_NOTICE_CHANGED_EVENT, changed);
    };
  }, []);

  const text = backupNoticeText(notice);
  if (!text) return null;
  return (
    <div role="status" data-ui="backup-notice" className="border-b border-amber-900/60 bg-amber-950/40 px-4 py-2 text-[13px] leading-5 text-amber-200 sm:px-6 sm:py-2.5 sm:text-sm">
      {text}{" "}
      <a href="/settings/backups" className="font-medium underline">
        {backupNoticeAction(notice)}
      </a>
    </div>
  );
}
