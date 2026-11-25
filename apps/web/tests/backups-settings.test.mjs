import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadBackups() {
  const result = ts.transpileModule(source("lib/backups-settings.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

const encryption = { encrypted: true, source: "key", optedOut: false, hasKey: true, keySaved: false, keySavedAt: null, keySavedBy: "", keyCreatedAt: null, canTurnOn: false, notice: "save-key" };

test("the heading and the sealed line are FTR's, with Hawk AI's settings", async () => {
  const { backupsHeading, sealedLine, READINESS, kb } = await loadBackups();
  assert.equal(backupsHeading({ intervalHours: 24, keep: 14 }), "nightly, before every version switch, and by hand · the newest 14 kept");
  assert.equal(backupsHeading({ intervalHours: 6, keep: 3 }), "every 6 hours, before every version switch, and by hand · the newest 3 kept");
  assert.deepEqual(sealedLine({ sealed: true, sealedBy: "environment", encryption }), { warn: false, text: "Sealed with BACKUP_PASSPHRASE." });
  assert.equal(sealedLine({ sealed: true, sealedBy: "key", encryption }).text, "Sealed with this server's backup key (below).");
  const plain = sealedLine({ sealed: false, sealedBy: "", encryption: { ...encryption, source: "none" } });
  assert.equal(plain.warn, true);
  assert.match(plain.text, /^anyone who gets a backup file can read everything in it/);
  assert.match(sealedLine({ sealed: false, sealedBy: "", encryption: { ...encryption, optedOut: true } }).text, /BACKUP_ENCRYPTION=off/);
  assert.deepEqual(READINESS, { ok: ["ok", "Ready"], todo: ["bad", "To do"], note: ["warn", "Check"] });
  assert.equal(kb(2048), "2 KB");
});

test("the notice, the key file and the restore question", async () => {
  const { backupNoticeText, backupNoticeAction, backupKeyFile, restoreQuestion } = await loadBackups();
  assert.match(backupNoticeText("save-key"), /nobody has confirmed saving the key/);
  assert.match(backupNoticeText("not-encrypted"), /not encrypted/);
  assert.equal(backupNoticeText(null), "");
  assert.equal(backupNoticeAction("save-key"), "Save the backup key");
  assert.equal(backupNoticeAction("not-encrypted"), "Turn on backup encryption");
  const file = backupKeyFile({ key: "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", host: "hawk-1", createdAt: null, saved: false }, new Date("2026-11-25T10:00:00Z"));
  assert.ok(file.startsWith("Hawk AI backup key\r\n\r\nAAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH\r\n"));
  assert.ok(file.includes("Server: hawk-1") && file.includes("2026-11-25 10:00 UTC") && file.includes("set BACKUP_PASSPHRASE to it"));
  const q = restoreQuestion({ createdAt: "x", files: 5, hasDatabase: true, dataFiles: 4 }, () => "25 Nov, 10:00");
  assert.match(q, /^Restore the backup of 25 Nov, 10:00 \(5 files: the database and 4 data folder files\)\?/);
});

test("the page keeps FTR's panels, controls and wording, at /settings/backups", () => {
  const page = source("app/settings/backups/page.tsx");
  for (const text of [
    "Backups &amp; health",
    "Backups <small>",
    "Back up now",
    "Kept in <span className=\"mono\">",
    "Backups go to their own place (BACKUP_DIR), away from the data: losing one disk does not lose both.",
    "Backups are in the data volume itself. Mount a second volume or a network share and set <b>BACKUP_DIR</b> to it, so losing one disk does not lose both.",
    "The last backup failed (",
    "No backups yet",
    "Download",
    "A backup file",
    "Its passphrase <span className=\"muted\">if sealed</span>",
    "Check and restore",
    "Health",
    "Repaired at start",
    "Download troubleshooting report",
    "Ready for production?",
    "What to put right before the server is opened to more people, and where. Looking changes nothing.",
    "As meant",
    "Ask again",
    // CxMissionZero's backup key box
    "Backup key",
    "Show backup key",
    "Download as a text file",
    "I have saved it",
    "Turn on backup encryption",
    "Nobody has confirmed saving this key yet.",
  ]) {
    assert.ok(page.includes(text), text);
  }
  for (const cls of ['className="grid g2"', 'className="panel"', 'className="tw mt"', 'className="form"', 'className="f"', 'className="ready-table"', "panel wide-panel mt", 'accept=".hkbackup"', 'className="danger"']) {
    assert.ok(page.includes(cls), cls);
  }
  assert.ok(page.includes('import "../ftr-settings.css"'));
  assert.ok(source("app/settings/https/page.tsx").includes('import "../ftr-settings.css"'));
  assert.match(source("lib/navigation.ts"), /href: "\/settings\/backups", label: "Backups & health"/);
  assert.match(source("components/app-shell.tsx"), /<BackupNotice \/>/);
  const css = source("app/settings/ftr-settings.css");
  for (const rule of [".ftr-settings .ready-table", ".ftr-settings td.actions", ".ftr-settings button.danger", ".ftr-settings .wide-panel"]) assert.ok(css.includes(rule), rule);
  for (const line of css.split("\n").filter((l) => /^[^\s/@:}].*\{/.test(l))) assert.match(line, /^\.ftr-settings/, line);
});

test("the backup before every version switch is the updater's, and the page says so", async () => {
  const { beforeUpdateLine } = await loadBackups();
  assert.equal(
    beforeUpdateLine({ last: { at: "2026-11-25T10:00:00Z", ok: true, name: "hawk-ai-2026-11-25T10-00-00.hkbackup", trigger: "Before the update to HK-00.03.00" } }),
    "The last backup was taken by the updater: Before the update to HK-00.03.00 (hawk-ai-2026-11-25T10-00-00.hkbackup).",
  );
  assert.equal(beforeUpdateLine({ last: { at: "", ok: true, trigger: "Scheduled" } }), "");
  assert.equal(beforeUpdateLine({ last: { at: "", ok: false, trigger: "Before the update to HK-00.03.00" } }), "");
  assert.equal(beforeUpdateLine({ last: null }), "");
});
