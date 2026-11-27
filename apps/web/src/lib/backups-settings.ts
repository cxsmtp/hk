/**
 * Settings → Backups & health: what the page shows, as FTR Command Center's page words it (public/js/settings.js
 * `backups()`), with the backup key of CxMissionZero (public/app/audit.js) in place of FTR's own passphrase form.
 * The API is app/api/routers/backups.py.
 */

export type BackupEncryption = {
  encrypted: boolean;
  source: "passphrase" | "key" | "none";
  optedOut: boolean;
  hasKey: boolean;
  keySaved: boolean;
  keySavedAt: string | null;
  keySavedBy: string;
  keyCreatedAt: string | null;
  canTurnOn: boolean;
  notice: BackupNotice;
};

export type BackupNotice = "save-key" | "not-encrypted" | null;

export type BackupFile = { name: string; at: string; bytes: number; size: number };

export type BackupsStatus = {
  backups: BackupFile[];
  sealed: boolean;
  sealedBy: "environment" | "key" | "";
  dir: string;
  // Where the backups are on the server (BACKUP_DIR, default HAWK_DATA_DIR/backups); "" when not known.
  hostDir?: string;
  separate: boolean;
  last: { at: string; ok: boolean; error?: string; name?: string; trigger?: string } | null;
  recovered: { at: string; target: string; action: string; details: { backup: string; kept: string } }[];
  dataDir: string;
  intervalHours: number;
  keep: number;
  encryption: BackupEncryption;
  pendingRestore: boolean;
  mailbox: { email: string; mailReady: boolean };
};

export type BackupKeyShown = { key: string; createdAt: string | null; saved: boolean; host: string };

export type BackupInfo = {
  createdAt: string;
  host: string;
  appVersion: string;
  files: number;
  bytes: number;
  hasDatabase: boolean;
  databaseBytes: number;
  dataFiles: number;
  hasSecrets: boolean;
  sha256: string;
};

export type ReadinessCheck = {
  id: string;
  title: string;
  state: "ok" | "todo" | "note";
  detail: string;
  where: string;
  canAccept?: boolean;
  accepted?: { by: string; at: string };
};

export type Readiness = { checks: ReadinessCheck[]; todo: number; notes: number };

/** The chips of "Ready for production?" (FTR's RD). */
export const READINESS: Record<ReadinessCheck["state"], [string, string]> = { ok: ["ok", "Ready"], todo: ["bad", "To do"], note: ["warn", "Check"] };

/** "nightly, before every version switch, and by hand · the newest 14 kept" (FTR's heading, with Hawk AI's settings). */
export function backupsHeading(b: Pick<BackupsStatus, "intervalHours" | "keep">): string {
  const when = b.intervalHours === 24 ? "nightly" : b.intervalHours > 0 ? `every ${b.intervalHours} hours` : "not on a schedule";
  return `${when}, before every version switch, and by hand · the newest ${b.keep} kept`;
}

/**
 * "before every version switch" made true: the updater (Settings → Updates) takes a backup before each update or
 * rollback, with the reason "Before the update to HK-…" (app/cli/backup.py --trigger). The last one, when it is that.
 */
export function beforeUpdateLine(b: Pick<BackupsStatus, "last">): string {
  const last = b.last;
  if (!last?.ok || !String(last.trigger ?? "").startsWith("Before the update")) return "";
  return `The last backup was taken by the updater: ${last.trigger} (${last.name ?? ""}).`;
}

/** What seals a backup made now, in FTR's words (Hawk AI's: BACKUP_PASSPHRASE, or the server's own backup key). */
export function sealedLine(b: Pick<BackupsStatus, "sealed" | "sealedBy" | "encryption">): { warn: boolean; text: string } {
  if (b.sealed) return { warn: false, text: b.sealedBy === "environment" ? "Sealed with BACKUP_PASSPHRASE." : "Sealed with this server's backup key (below)." };
  if (b.encryption.optedOut) return { warn: true, text: "anyone who gets a backup file can read everything in it (BACKUP_ENCRYPTION=off is set on the server)." };
  return { warn: true, text: "anyone who gets a backup file can read everything in it. Turn encryption on below." };
}

/** The notice owners and admins see at the top of every page until they act (CxMissionZero's backup banner). */
export function backupNoticeText(notice: BackupNotice): string {
  if (notice === "save-key")
    return "Backups are encrypted with this server's backup key, and nobody has confirmed saving the key somewhere else yet. If this server is lost, its backups open only with that key.";
  if (notice === "not-encrypted")
    return "Backups of this server are not encrypted: each one holds the password hashes, the connector keys and the certificate keys in the clear.";
  return "";
}

export const backupNoticeAction = (notice: BackupNotice): string => (notice === "save-key" ? "Save the backup key" : notice === "not-encrypted" ? "Turn on backup encryption" : "");

/** The text file "Download as a text file" saves (CxMissionZero's, for Hawk AI). */
export function backupKeyFile(shown: BackupKeyShown, now = new Date()): string {
  return [
    "Hawk AI backup key",
    "",
    shown.key,
    "",
    `Server: ${shown.host}`,
    `Saved from Settings → Backups & health: ${now.toISOString().slice(0, 16).replace("T", " ")} UTC`,
    "",
    "Keep this file somewhere other than the server. Anyone who has it and a backup can read everything in the backup.",
    "To restore a backup on another server: give this key when the restore asks for it, or set BACKUP_PASSPHRASE to it.",
    "",
  ].join("\r\n");
}

/** "Restore the backup of … ?" (FTR's question, with what a Hawk AI backup holds). */
export function restoreQuestion(info: BackupInfo, when: (iso: string) => string): string {
  const parts = [info.hasDatabase ? "the database" : "", `${info.dataFiles} data folder file${info.dataFiles === 1 ? "" : "s"}`].filter(Boolean).join(" and ");
  return `Restore the backup of ${when(info.createdAt)} (${info.files} files: ${parts})?\n\nEverything here is replaced when Hawk AI next starts. What is here now is kept aside on the server first.`;
}

export const kb = (bytes: number): string => `${(bytes / 1024).toFixed(0)} KB`;
