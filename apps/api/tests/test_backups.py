"""Backups and restore, ported from CxMissionZero (src/backup.js, src/backup-key.js, src/mail-inbox.js,
scripts/backup.mjs, scripts/restore.mjs, the backup parts of src/server.js and src/routes/backups.js): the one-file
archive and its checksums, encryption and the server's own key, retention and the schedule, the restore (dry run,
apply, refusals), the backup mailbox and the restore from it, the backup before a stop, and the Settings routes."""

from __future__ import annotations

import base64
import datetime as dt
import email.utils
import gzip
import json
import os
import re
import time
from email.message import EmailMessage
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.cli import backup as backup_cli
from app.cli import prestart as prestart_cli
from app.cli import restore as restore_cli
from app.db.models.audit import AuditLog
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.jobs import backup_jobs
from app.main import app
from app.services import backup_archive as archive
from app.services import backup_service, mail_inbox, mailer
from app.services.backup_key import ALPHABET, BackupKeyStore, canonical_backup_key, earlier_state, generate_backup_key

DUMP = b"PGDMP-fake-custom-format-dump"


def cfg_for(tmp_path: Path, **kw) -> backup_service.BackupConfig:
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    return backup_service.BackupConfig(
        data_dir=data,
        dir=kw.get("dir", data / "backups"),
        explicit_dir=kw.get("explicit_dir", False),
        interval_hours=kw.get("interval_hours", 24),
        keep=kw.get("keep", 14),
        database_url="postgresql+psycopg2://hawk:pw@postgres:5432/hawk",
    )


def fill_data(data: Path) -> None:
    (data / "https.json").write_text('{"mode": "both"}')
    (data / "tls").mkdir(exist_ok=True)
    (data / "tls" / "self-signed.crt").write_text("CERT")
    (data / "tls" / "self-signed.key").write_text("KEY")
    (data / "backup-key.json").write_text('{"mode": "encrypted", "key": "SECRET"}')
    (data / "first-admin-password.txt").write_text("one-time")
    (data / "https.json.bak").write_text("{}")
    (data / ".https.json.abcd.tmp").write_text("half")
    (data / "backups").mkdir(exist_ok=True)
    (data / "backups" / "hawk-ai-old.hkbackup").write_bytes(b"x")
    (data / "replaced-2026-01-01").mkdir(exist_ok=True)
    (data / "replaced-2026-01-01" / "https.json").write_text("{}")


def make(data: Path, passphrase: str = "", **kw) -> tuple[bytes, dict]:
    return archive.create_backup(data_dir=data, database_dump=DUMP, passphrase=passphrase, app_secrets={"SECRET_KEY": b"k1"}, app_version="1.2.3", **kw)


# ---- The archive --------------------------------------------------------------------------------------------------


def test_one_file_holds_the_database_and_the_data_folder_but_never_the_key_or_the_backups(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    fill_data(data)
    buffer, summary = make(data)
    assert buffer[:2] == b"\x1f\x8b" and summary["encrypted"] is False and summary["database"] is True
    bundle = archive.read_backup(buffer)
    assert sorted(bundle["files"]) == ["data/https.json", "data/tls/self-signed.crt", "data/tls/self-signed.key", "database.pgdump", "secrets/SECRET_KEY"]
    assert archive.member(bundle, "database.pgdump") == DUMP
    info = archive.describe_backup(bundle)
    assert info["hasDatabase"] and info["dataFiles"] == 3 and info["hasSecrets"] and info["appVersion"] == "1.2.3"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z", info["createdAt"])
    # A BACKUP_DIR inside the data folder under another name is left out too.
    (data / "store").mkdir()
    (data / "store" / "hawk-ai-x.hkbackup").write_bytes(b"x")
    names = [n for n, _ in archive.collect_data_files(data, backup_dir=data / "store")]
    assert "data/store/hawk-ai-x.hkbackup" not in names


def test_a_damaged_backup_is_refused_whole(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    fill_data(data)
    buffer, _ = make(data)
    bundle = json.loads(gzip.decompress(buffer))

    def repack(b: dict) -> bytes:
        return gzip.compress(json.dumps(b).encode())

    tampered = json.loads(json.dumps(bundle))
    tampered["files"]["data/https.json"]["data"] = base64.b64encode(b'{"mode": "http"}').decode()
    with pytest.raises(archive.BackupError, match="data/https.json is damaged"):
        archive.read_backup(repack(tampered))
    # Every file's hash fixed up, the overall checksum is still wrong.
    forged = json.loads(json.dumps(bundle))
    new = b'{"mode": "http"}'
    forged["files"]["data/https.json"] = {"data": base64.b64encode(new).decode(), "size": len(new), "sha256": archive.sha256(new)}
    with pytest.raises(archive.BackupError, match="do not match its checksum"):
        archive.read_backup(repack(forged))
    dropped = json.loads(json.dumps(bundle))
    del dropped["files"]["database.pgdump"]
    with pytest.raises(archive.BackupError, match="checksum"):
        archive.read_backup(repack(dropped))
    with pytest.raises(archive.BackupError, match="Not a Hawk AI backup"):
        archive.read_backup(buffer[: len(buffer) // 2])
    with pytest.raises(archive.BackupError, match="Not a Hawk AI backup"):
        archive.read_backup(b"hello")
    newer = dict(bundle, version=2)
    with pytest.raises(archive.BackupError, match="version 2 is newer"):
        archive.read_backup(repack(newer))
    with pytest.raises(archive.BackupError, match="more than 1 MB"):
        archive.read_backup(gzip.compress(b" " * (2 * 1024 * 1024)), max_unpacked_bytes=1024 * 1024)


@pytest.mark.parametrize("name", ["data/../etc/passwd", "data/backup-key.json", "data/backups/x.hkbackup", "/etc/passwd", "secrets/OTHER", "data/replaced-1/x", "data/.hidden", "notes.txt"])
def test_names_out_of_the_data_folder_or_kept_out_are_refused(name):
    content = b"x"
    files = {name: {"data": base64.b64encode(content).decode(), "size": 1, "sha256": archive.sha256(content)}}
    bundle = {"format": archive.BACKUP_FORMAT, "version": 1, "createdAt": "", "host": "", "files": files, "sha256": archive.manifest_hash(files)}
    with pytest.raises(archive.BackupError, match="unexpected file name"):
        archive.read_backup(gzip.compress(json.dumps(bundle).encode()))


def test_encrypted_with_aes_gcm_and_scrypt_opens_only_with_its_key(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    fill_data(data)
    key = generate_backup_key()
    buffer, summary = make(data, passphrase=key)
    assert summary["encrypted"] and archive.is_sealed(buffer) and buffer.startswith(b"HKBK1\n")
    header = json.loads(buffer[6 : buffer.index(b"\n", 6)])
    assert header["format"] == "hawk-ai-backup-sealed" and header["kdf"] == "scrypt"
    assert b"self-signed" not in buffer and b"PGDMP" not in buffer
    with pytest.raises(archive.BackupKeyError) as needed:
        archive.read_backup(buffer)
    assert needed.value.code == "BACKUP_KEY_NEEDED"
    with pytest.raises(archive.BackupKeyError) as wrong:
        archive.read_backup(buffer, passphrase="not it")
    assert wrong.value.code == "BACKUP_KEY_WRONG"
    # The key as someone types it: lower case, spaces for the dashes.
    typed = key.lower().replace("-", " ")
    assert archive.member(archive.read_backup(buffer, passphrases=["nope", typed]), "database.pgdump") == DUMP
    flipped = bytearray(buffer)
    flipped[-5] ^= 1
    with pytest.raises(archive.BackupKeyError):
        archive.read_backup(bytes(flipped), passphrase=key)


def test_retention_keeps_the_newest_and_lists_newest_first(tmp_path):
    folder = tmp_path / "b"
    base = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
    for day in range(16):
        archive.write_backup_to(folder, b"x", keep=14, now=base + dt.timedelta(days=day))
    listed = archive.list_backups(folder)
    assert len(listed) == 14 and listed[0]["name"] == "hawk-ai-2026-11-16T00-00-00.hkbackup" and listed[-1]["name"].startswith("hawk-ai-2026-11-03")
    assert oct(os.stat(folder / listed[0]["name"]).st_mode & 0o777) == "0o600"
    assert archive.prune(folder, 0) and len(archive.list_backups(folder)) == 1


# ---- The server's backup key --------------------------------------------------------------------------------------


def test_the_key_is_8_groups_of_4_easy_letters_and_is_read_however_typed():
    key = generate_backup_key()
    assert re.fullmatch(r"([A-Z2-9]{4}-){7}[A-Z2-9]{4}", key) and not set(key.replace("-", "")) - set(ALPHABET)
    assert not {"I", "O", "0", "1"} & set(key)
    assert canonical_backup_key(key.lower().replace("-", "  ")) == key
    assert canonical_backup_key("a passphrase of my own") == ""


def test_a_new_installation_encrypts_with_its_own_key_and_an_existing_one_is_left_plain(tmp_path):
    new = tmp_path / "new"
    new.mkdir()
    store = BackupKeyStore(data_dir=new, env={})
    decision = store.decide(has_people=lambda: False)
    assert decision["decidedBy"] == "new-installation" and store.source == "key" and store.status()["notice"] == "save-key"
    assert oct(os.stat(new / "backup-key.json").st_mode & 0o777) == "0o600"
    assert store.decide(has_people=lambda: True) is None  # decided once, never again
    assert BackupKeyStore(data_dir=new, env={}).source == "key"

    old = tmp_path / "old"
    old.mkdir()
    (old / "https.json").write_text("{}")
    store = BackupKeyStore(data_dir=old, env={})
    assert store.decide(has_people=lambda: False)["found"] == "https.json"
    assert store.source == "none" and store.secret() == "" and store.status()["notice"] == "not-encrypted" and store.status()["canTurnOn"]

    people = tmp_path / "people"
    people.mkdir()
    assert BackupKeyStore(data_dir=people, env={}).decide(has_people=lambda: True)["decidedBy"] == "existing-installation"
    doubt = tmp_path / "doubt"
    doubt.mkdir()
    assert BackupKeyStore(data_dir=doubt, env={}).decide(has_people=lambda: 1 / 0)["decidedBy"] == "existing-installation"
    plain_backup = tmp_path / "plainbk"
    (plain_backup / "backups").mkdir(parents=True)
    (plain_backup / "backups" / "hawk-ai-1.hkbackup").write_bytes(b"\x1f\x8b plain")
    assert "not encrypted" in earlier_state(data_dir=plain_backup)


def test_passphrase_wins_opt_out_turning_on_and_saving_the_key(tmp_path):
    data = tmp_path / "d"
    data.mkdir()
    store = BackupKeyStore(data_dir=data, env={"BACKUP_ENCRYPTION": "off"})
    assert store.decide(has_people=lambda: False)["decidedBy"] == "opt-out"
    assert store.status() | {} == store.status() and store.status()["notice"] is None and not store.status()["canTurnOn"]
    store = BackupKeyStore(data_dir=data, env={"BACKUP_ENCRYPTION": "off", "BACKUP_PASSPHRASE": "pass phrase"})
    assert store.source == "passphrase" and store.secret() == "pass phrase"
    store = BackupKeyStore(data_dir=data, env={})
    assert store.turn_on(by="a@x") and store.source == "key" and not store.turn_on()
    key = store.reveal()
    assert store.candidates() == [key] and store.status()["notice"] == "save-key"
    assert store.confirm_saved(by="a@x") and store.status()["keySaved"] and store.status()["notice"] is None
    assert key not in json.dumps(store.status())
    file = tmp_path / "f"
    file.mkdir()
    (file / "backup-key.json").write_text("{damaged")
    with pytest.raises(Exception, match="backup-key.json"):
        BackupKeyStore(data_dir=file, env={})


# ---- Making backups: the schedule, the folder, the mailbox ---------------------------------------------------------


def test_the_first_backup_is_a_minute_after_start_then_every_interval():
    clock = {"now": dt.datetime(2026, 11, 25, 10, 0, tzinfo=dt.timezone.utc)}
    s = backup_jobs.FirstSoonThenEvery(dt.timedelta(hours=24), nowfun=lambda: clock["now"])
    start = clock["now"]
    due, wait = s.is_due(start)
    assert not due and wait == 60
    clock["now"] = start + dt.timedelta(seconds=59)
    assert not s.is_due(start)[0]
    clock["now"] = start + dt.timedelta(seconds=60)
    due, wait = s.is_due(start)
    assert due and wait == 24 * 3600
    ran = clock["now"]
    clock["now"] = ran + dt.timedelta(hours=23)
    assert not s.is_due(ran)[0]
    clock["now"] = ran + dt.timedelta(hours=24, seconds=1)
    assert s.is_due(ran)[0]
    entry = backup_jobs.beat_entry({})
    assert entry["task"] == backup_jobs.TASK_NAME and entry["schedule"].run_every == dt.timedelta(hours=24)
    assert backup_jobs.beat_entry({"BACKUP_INTERVAL_HOURS": "6"})["schedule"].run_every == dt.timedelta(hours=6)
    assert backup_jobs.beat_entry({"BACKUP_INTERVAL_HOURS": "0"}) is None
    import pickle

    assert pickle.loads(pickle.dumps(entry["schedule"])) == entry["schedule"]


def test_config_defaults_and_the_same_disk_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_service.settings, "hawk_data_dir", str(tmp_path / "data"))
    c = backup_service.config({})
    assert (c.interval_hours, c.keep, c.explicit_dir) == (24, 14, False) and c.dir == (tmp_path / "data" / "backups").resolve() and c.same_disk
    c = backup_service.config({"BACKUP_DIR": str(tmp_path / "data" / "elsewhere"), "BACKUP_KEEP": "0", "BACKUP_INTERVAL_HOURS": "6"})
    assert c.keep == 1 and c.interval_hours == 6 and c.same_disk


def test_a_backup_to_the_folder_is_audited_remembered_and_emailed_only_encrypted(tmp_path, monkeypatch):
    cfg = cfg_for(tmp_path, keep=2)
    fill_data(cfg.data_dir)
    (cfg.data_dir / "backup-key.json").unlink()
    store = BackupKeyStore(data_dir=cfg.data_dir, env={})
    store.decide(has_people=lambda: True)  # existing: plain
    events, sent = [], []
    audit = lambda action, reason, **kw: events.append((action, reason))  # noqa: E731
    monkeypatch.setenv("BACKUP_EMAIL", "Backups@Acme.io")
    monkeypatch.setattr(mailer, "smtp_from_env", lambda env=None: mailer.SmtpSettings(host="smtp.acme.io", user="hawk@acme.io"))
    monkeypatch.setattr(mailer, "send_mail", lambda to, **kw: sent.append((to, kw)))
    last = backup_service.backup_to_folder("Manual", cfg=cfg, audit=audit, dump=lambda url: DUMP)
    assert last["ok"] and not last["encrypted"] and Path(last["file"]).exists() and backup_service.last_backup(cfg)["name"] == last["name"]
    assert events[0][0] == "backup.written" and sent == []  # never emailed plain
    store.turn_on()
    for _ in range(3):
        time.sleep(1.01)
        last = backup_service.backup_to_folder("Scheduled", cfg=cfg, audit=audit, dump=lambda url: DUMP)
    assert last["encrypted"] and len(archive.list_backups(cfg.dir)) == 2
    to, kw = sent[-1]
    assert to == ["backups@acme.io"] and kw["subject"].startswith("Hawk AI backup ") and kw["subject"].endswith(" UTC")
    assert kw["attachments"][0][0] == last["name"] and archive.is_sealed(kw["attachments"][0][1])
    assert store.reveal() not in kw["text"] and "backup key" in kw["text"]
    assert ("backup.emailed", f"Scheduled backup emailed to backups@acme.io ({last['name']}).") in events
    monkeypatch.setattr(backup_service, "MAX_ATTACHMENT_BYTES", 10)
    sent.clear()
    backup_service.backup_to_folder("Manual", cfg=cfg, audit=audit, dump=lambda url: DUMP)
    assert sent == [] and events[-1][0] == "backup.email.skipped"
    failed = backup_service.backup_to_folder("Manual", cfg=cfg, audit=audit, dump=lambda url: (_ for _ in ()).throw(RuntimeError("pg_dump failed: no")))
    assert not failed["ok"] and "pg_dump failed" in failed["error"] and events[-1][0] == "backup.failed"


def test_the_backup_cli_writes_an_encrypted_file_that_reads_back(tmp_path, capsys):
    cfg = cfg_for(tmp_path)
    fill_data(cfg.data_dir)
    (cfg.data_dir / "backup-key.json").unlink()
    BackupKeyStore(data_dir=cfg.data_dir, env={}).turn_on()
    assert backup_cli.main([str(tmp_path / "out") + "/"], cfg=cfg, dump=lambda url: DUMP) == 0
    out = capsys.readouterr().out
    assert "encrypted with the server's backup key" in out and "Nobody has confirmed saving the backup key" in out
    (file,) = list((tmp_path / "out").iterdir())
    assert archive.is_sealed(file.read_bytes())


# ---- Restoring --------------------------------------------------------------------------------------------------


def staged_world(tmp_path):
    cfg = cfg_for(tmp_path)
    fill_data(cfg.data_dir)
    buffer, _ = make(cfg.data_dir)
    (cfg.data_dir / "https.json").write_text('{"mode": "https"}')
    (cfg.data_dir / "acme.json").write_text("{}")  # made after the backup
    return cfg, buffer


def test_restore_puts_what_was_there_aside_then_the_backups_database_and_files_in_place(tmp_path):
    cfg, buffer = staged_world(tmp_path)
    put = []
    done = backup_service.restore_bundle(archive.read_backup(buffer), cfg=cfg, restore_db=lambda url, dump: put.append(dump), dump=lambda url: b"OLD-DB", env={"SECRET_KEY": "k2"})
    assert put == [DUMP] and done["databaseRestored"]
    replaced = Path(done["replacedDir"])
    assert replaced.parent == cfg.data_dir and replaced.name.startswith("replaced-")
    assert (replaced / "database.pgdump").read_bytes() == b"OLD-DB" and (replaced / "acme.json").exists()
    assert json.loads((replaced / "https.json").read_text()) == {"mode": "https"}
    assert json.loads((cfg.data_dir / "https.json").read_text()) == {"mode": "both"} and not (cfg.data_dir / "acme.json").exists()
    # Kept: this server's own key, its backups, the first administrator's file is put aside with the rest.
    assert (cfg.data_dir / "backup-key.json").exists() and (cfg.data_dir / "backups" / "hawk-ai-old.hkbackup").exists()
    assert (replaced / "first-admin-password.txt").exists() or (cfg.data_dir / "first-admin-password.txt").exists()
    assert done["secretsDiffer"] == ["SECRET_KEY"] and (cfg.data_dir / "restored-secrets" / "secret_key").read_text() == "k1"
    assert any("restored-secrets" in line for line in backup_service.secrets_instructions(done))


def test_a_failed_database_restore_touches_no_file(tmp_path):
    cfg, buffer = staged_world(tmp_path)
    calls = []

    def put(url, dump):
        calls.append(dump)
        if dump == DUMP:
            raise RuntimeError("pg_restore failed")

    with pytest.raises(RuntimeError):
        backup_service.restore_bundle(archive.read_backup(buffer), cfg=cfg, restore_db=put, dump=lambda url: b"OLD-DB", env={})
    assert calls == [DUMP]
    assert json.loads((cfg.data_dir / "https.json").read_text()) == {"mode": "https"}  # files untouched


class Lock:
    def __init__(self, free=True):
        self.free = free
        self.released = False

    def __call__(self, url):
        return self

    def try_acquire(self, **kw):
        return self.free

    def holders(self):
        return 0 if self.free else 3

    def release(self):
        self.released = True


def test_restore_cli_dry_run_writes_nothing_and_yes_refuses_while_hawk_runs(tmp_path, capsys):
    cfg, buffer = staged_world(tmp_path)
    file = tmp_path / "b.hkbackup"
    file.write_bytes(buffer)
    restored = []
    fake = lambda bundle, cfg: restored.append(bundle) or {"restored": [], "replacedDir": None, "databaseRestored": True, "secretsDiffer": []}  # noqa: E731
    assert restore_cli.main([str(file)], cfg=cfg, restore=fake, audit=lambda *a, **k: None) == 0
    out = capsys.readouterr().out
    assert "checksum OK" in out and "Nothing written" in out and "database: yes" in out and restored == []
    lock = Lock(free=False)
    assert restore_cli.main([str(file), "--yes"], cfg=cfg, lock_factory=lock, restore=fake, audit=lambda *a, **k: None) == 1
    err = capsys.readouterr().err
    assert "Hawk AI is running on this database (3 of api, worker and beat)" in err and "--force" in err and restored == [] and lock.released
    events = []
    assert restore_cli.main([str(file), "--yes", "--force"], cfg=cfg, lock_factory=Lock(False), restore=fake, audit=lambda *a, **k: events.append(a)) == 0
    assert len(restored) == 1 and events[0][0] == "backup.restored"
    assert restore_cli.main([str(file), "--yes"], cfg=cfg, lock_factory=Lock(True), restore=fake, audit=lambda *a, **k: None) == 0
    assert len(restored) == 2
    assert restore_cli.main([], cfg=cfg) == 2


def test_restore_cli_asks_for_the_key_and_a_rebuilt_server_keeps_it(tmp_path, capsys, monkeypatch):
    cfg = cfg_for(tmp_path)
    fill_data(cfg.data_dir)
    key = generate_backup_key()
    buffer, _ = make(cfg.data_dir, passphrase=key)
    file = tmp_path / "b.hkbackup"
    file.write_bytes(buffer)
    (cfg.data_dir / "backup-key.json").unlink()
    fake = lambda bundle, cfg: {"restored": ["data/https.json"], "replacedDir": None, "databaseRestored": True, "secretsDiffer": []}  # noqa: E731
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    assert restore_cli.main([str(file)], cfg=cfg, restore=fake) == 1
    assert "no backup key or passphrase was given" in capsys.readouterr().err
    monkeypatch.setenv("BACKUP_PASSPHRASE", "wrong one")
    assert restore_cli.main([str(file)], cfg=cfg, restore=fake) == 1
    assert "did not open with the BACKUP_PASSPHRASE given" in capsys.readouterr().err
    monkeypatch.setenv("BACKUP_PASSPHRASE", key.lower())
    assert restore_cli.main([str(file), "--yes"], cfg=cfg, lock_factory=Lock(), restore=fake, audit=lambda *a, **k: None) == 0
    assert "goes on encrypting its backups with the same backup key" in capsys.readouterr().out
    assert BackupKeyStore(data_dir=cfg.data_dir, env={}).reveal() == key
    # The same data folder's own key opens its backup without BACKUP_PASSPHRASE.
    monkeypatch.delenv("BACKUP_PASSPHRASE")
    assert restore_cli.main([str(file)], cfg=cfg, restore=fake) == 0


def test_a_staged_restore_is_applied_at_the_next_start_unless_hawk_still_runs(tmp_path, capsys):
    cfg, buffer = staged_world(tmp_path)
    archive.stage_restore(archive.read_backup(buffer), cfg.data_dir)
    migrated, events = [], []
    opts = dict(restore_db=lambda url, dump: None, dump=lambda url: b"OLD", env={})
    prestart_cli.main(cfg=cfg, migrate=lambda: migrated.append(1), lock_factory=Lock(False), audit=lambda *a, **k: events.append(a), **opts)
    assert (cfg.data_dir / archive.PENDING_RESTORE).exists() and migrated == [1] and events == []
    assert "it was not applied" in capsys.readouterr().out
    prestart_cli.main(cfg=cfg, migrate=lambda: migrated.append(2), lock_factory=Lock(True), audit=lambda *a, **k: events.append(a), **opts)
    assert not (cfg.data_dir / archive.PENDING_RESTORE).exists() and migrated == [1, 2]
    assert events[0][0] == "backup.restored" and json.loads((cfg.data_dir / "https.json").read_text()) == {"mode": "both"}


# ---- The backup mailbox -------------------------------------------------------------------------------------------


class FakeImap:
    """Just enough of imaplib.IMAP4 for the mailbox: it records what was asked, and refuses anything that writes."""

    def __init__(self, messages):
        self.messages = messages  # uid → raw bytes
        self.calls = []

    def login(self, user, password):
        self.calls.append(("login", user))
        return "OK", [b"ok"]

    def select(self, box, readonly=False):
        assert readonly, "the mailbox is only ever opened read-only"
        self.calls.append(("select", box))
        return "OK", [b"1"]

    def uid(self, command, *args):
        self.calls.append((command, args))
        if command == "SEARCH":
            return "OK", [b" ".join(self.messages)]
        if command == "FETCH":
            uid, spec = args
            assert "PEEK" in spec, "nothing is marked read"
            raw = self.messages[uid]
            if "HEADER.FIELDS" in spec:
                head = raw.split(b"\n\n", 1)[0] + b"\n\n"
                return "OK", [(f"1 (UID {uid.decode()} RFC822.SIZE {len(raw)} BODY[HEADER.FIELDS (DATE SUBJECT)] {{{len(head)}}}".encode(), head), b")"]
            return "OK", [(f"1 (UID {uid.decode()} BODY[] {{{len(raw)}}}".encode(), raw), b")"]
        raise AssertionError(f"unexpected {command}")

    def logout(self):
        self.calls.append(("logout",))


def mail(subject: str, when: dt.datetime, attachment: bytes | None, name: str = "hawk-ai-x.hkbackup") -> bytes:
    m = EmailMessage()
    m["Subject"] = subject
    m["Date"] = email.utils.format_datetime(when)
    m["From"] = "hawk@acme.io"
    m.set_content("backup")
    if attachment is not None:
        m.add_attachment(attachment, maintype="application", subtype="octet-stream", filename=name)
    return m.as_bytes()


def test_the_newest_backup_that_opens_is_found_and_nothing_in_the_mailbox_changes(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    fill_data(data)
    good_old, _ = make(data, passphrase="pass")
    (data / "https.json").write_text('{"mode": "http"}')
    good_new, _ = make(data, passphrase="pass")
    planted, _ = make(data, passphrase="someone else's")
    plain, _ = make(data)
    t = dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc)
    messages = {
        b"1": mail("Hawk AI backup 2026-11-20 02:00 UTC", t, good_old, "old.hkbackup"),
        b"2": mail("Hawk AI backup 2026-11-21 02:00 UTC", t + dt.timedelta(days=1), good_new, "new.hkbackup"),
        b"3": mail("Hawk AI backup 2026-11-22 02:00 UTC", t + dt.timedelta(days=2), planted),
        b"4": mail("Hawk AI backup 2026-11-23 02:00 UTC", t + dt.timedelta(days=3), plain),
        b"5": mail("Re: Hawk AI backup", t + dt.timedelta(days=4), good_new),
    }
    imap = FakeImap(messages)
    opened = {}

    def accept(buffer):
        if not archive.is_sealed(buffer):
            return False
        try:
            opened["b"] = archive.read_backup(buffer, passphrase="pass")
            return True
        except archive.BackupError:
            return False

    found = mail_inbox.find_backup_in_mailbox(mail_inbox.MailboxAccount(host="imap.acme.io", user="b@acme.io", password="pw"), accept, connect=lambda a: imap)
    assert found["name"] == "new.hkbackup" and found["date"] == "2026-11-21T00:00:00Z"
    assert json.loads(archive.member(opened["b"], "data/https.json")) == {"mode": "http"}
    assert ("SEARCH", (None, "SUBJECT", '"Hawk AI backup"')) in imap.calls and imap.calls[-1] == ("logout",)
    assert not any(c[0] in ("STORE", "COPY", "MOVE", "EXPUNGE") for c in imap.calls)
    # Only the newest 20 are looked at.
    many = {str(i).encode(): mail("Hawk AI backup", t + dt.timedelta(hours=i), b"junk") for i in range(1, 31)}
    seen = FakeImap(many)
    assert mail_inbox.find_backup_in_mailbox(mail_inbox.MailboxAccount(host="h"), lambda b: False, connect=lambda a: seen) is None
    assert len([c for c in seen.calls if c[0] == "FETCH" and "HEADER" in c[1][1]]) == 20


def test_without_starttls_the_password_is_never_sent(monkeypatch):
    class Plain:
        capabilities = ("IMAP4REV1", "AUTH=PLAIN")

        def __init__(self, *a, **k):
            pass

        def shutdown(self):
            pass

    monkeypatch.setattr(mail_inbox.imaplib, "IMAP4", Plain)
    with pytest.raises(mail_inbox.MailboxError, match="never sends a password without one"):
        mail_inbox.find_backup_in_mailbox(mail_inbox.MailboxAccount(host="imap.acme.io", port=143, user="u", password="secret-pw"), lambda b: True)

    def boom(account):
        raise OSError("login failed for secret-pw")

    with pytest.raises(mail_inbox.MailboxError) as error:
        mail_inbox.find_backup_in_mailbox(mail_inbox.MailboxAccount(host="h", password="secret-pw"), lambda b: True, connect=boom)
    assert "secret-pw" not in str(error.value) and "[hidden]" in str(error.value)


def test_a_new_empty_server_restores_itself_from_the_mailbox(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    fill_data(source)
    buffer, _ = make(source, passphrase="pass")
    cfg = cfg_for(tmp_path)
    env = {"BACKUP_EMAIL": "b@acme.io", "BACKUP_EMAIL_PASSWORD": "pw", "SMTP_HOST": "mail.acme.io", "BACKUP_PASSPHRASE": "pass"}
    imap = FakeImap({b"1": mail("Hawk AI backup 2026-11-21 02:00 UTC", dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc), buffer)})
    accounts = []

    def find(account, accept):
        accounts.append(account)
        return mail_inbox.find_backup_in_mailbox(account, accept, connect=lambda a: imap)

    # Not a new server: nothing is looked at.
    assert backup_service.restore_from_mailbox_at_start(cfg, env=env, people=lambda: True, find=find) is None and accounts == []
    # Missing the passphrase: nothing either.
    assert backup_service.restore_from_mailbox_at_start(cfg, env={**env, "BACKUP_PASSPHRASE": ""}, people=lambda: False, find=find) is None
    found = backup_service.restore_from_mailbox_at_start(cfg, env=env, people=lambda: False, find=find)
    assert found["mailbox"] == "b@acme.io" and (cfg.data_dir / archive.PENDING_RESTORE).exists()
    assert accounts[0].host == "mail.acme.io" and accounts[0].port == 993 and accounts[0].user == "b@acme.io"
    # Staged decrypted, then applied as any staged restore.
    done = backup_service.apply_pending_restore(cfg, restore_db=lambda url, dump: None, dump=lambda url: b"", env={})
    assert json.loads((cfg.data_dir / "https.json").read_text()) == {"mode": "both"} and done["databaseRestored"]
    # A mailbox that does not answer within the time: the server starts fresh.
    cfg2 = cfg_for(tmp_path / "two")
    slow = lambda account, accept: time.sleep(5)  # noqa: E731
    assert backup_service.restore_from_mailbox_at_start(cfg2, env=env, people=lambda: False, find=slow, timeout=0.2) is None
    assert "did not answer within 0 seconds" in capsys.readouterr().out
    # Nothing that opens: fresh too.
    other = FakeImap({b"1": mail("Hawk AI backup", dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc), make(source, passphrase="other")[0])})
    assert backup_service.restore_from_mailbox_at_start(cfg2, env=env, people=lambda: False, find=lambda a, acc: mail_inbox.find_backup_in_mailbox(a, acc, connect=lambda x: other)) is None


# ---- Before stopping -----------------------------------------------------------------------------------------------


def test_last_words_back_up_and_mail_the_admins_at_most_every_six_hours(tmp_path):
    cfg = cfg_for(tmp_path)
    fill_data(cfg.data_dir)
    (cfg.data_dir / "backup-key.json").unlink()
    store = BackupKeyStore(data_dir=cfg.data_dir, env={})
    store.turn_on()
    sent = []
    clock = {"t": 1_800_000_000.0}
    kw = dict(cfg=cfg, env={}, audit=lambda *a, **k: None, dump=lambda url: DUMP, send=lambda to, **m: sent.append((to, m)), admins=lambda: ["a@acme.io", "b@acme.io"], now=lambda: clock["t"])
    first = backup_service.last_words("the service was stopped", time.monotonic() + 5, **kw)
    assert first["backup"]["ok"] and first["mailed"] == 2 and not first["throttled"]
    to, m = sent[0]
    assert m["subject"] == "Hawk AI stopped: a copy of its data is safe" and m["attachments"][0][0] == first["backup"]["name"]
    assert store.reveal() not in m["text"] and "Nobody has confirmed saving the backup key yet" in m["text"]
    clock["t"] += 5 * 3600
    again = backup_service.last_words("the service was stopped", time.monotonic() + 5, **kw)
    assert again["backup"]["ok"] and again["throttled"] and len(sent) == 2  # a backup, but no second email
    # Plain backups (BACKUP_ENCRYPTION=off): the email says where the backup is, and attaches nothing.
    os.environ["BACKUP_ENCRYPTION"] = "off"
    try:
        clock["t"] += 7 * 3600
        sent.clear()
        plain = backup_service.last_words("the service was stopped", time.monotonic() + 5, **kw)
        to, m = sent[0]
        assert m["attachments"] == [] and "not attached because it is not encrypted" in m["text"] and plain["backup"]["file"] in m["text"]
    finally:
        del os.environ["BACKUP_ENCRYPTION"]


# ---- The mailer ------------------------------------------------------------------------------------------------------


def test_the_mailer_reads_cxmissionzeros_smtp_settings_and_hides_the_password():
    assert mailer.smtp_from_env({}) is None
    s = mailer.smtp_from_env({"SMTP_HOST": "smtp.acme.io", "SMTP_USER": "hawk@acme.io", "SMTP_PASS": "pw-123", "SMTP_FROM_NAME": "Hawk AI"})
    assert (s.port, s.secure, s.require_auth, s.reject_unauthorized) == (587, False, True, True)
    assert s.sender == "Hawk AI <hawk@acme.io>"
    s = mailer.smtp_from_env({"SMTP_HOST": "smtp.acme.io", "SMTP_SECURE": "true", "SMTP_PASSWORD": "x", "SMTP_FROM": "a@acme.io", "SMTP_REJECT_UNAUTHORIZED": "false"})
    assert s.port == 465 and s.secure and not s.require_auth and not s.reject_unauthorized and s.password == "x"
    secret = mailer.SmtpSettings(host="h", user="u", password="pw-123")
    assert mailer.redact_secrets(f"no {base64.b64encode(b'pw-123').decode()} pw-123", secret) == "no [hidden] [hidden]"


# ---- The routes: owners and admins, audited -----------------------------------------------------------------------


@pytest.fixture()
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'b.sqlite3'}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    cfg = cfg_for(tmp_path)
    fill_data(cfg.data_dir)
    (cfg.data_dir / "backup-key.json").unlink()
    BackupKeyStore(data_dir=cfg.data_dir, env={}).turn_on()
    monkeypatch.setattr(backup_service, "config", lambda env=None: cfg)
    monkeypatch.setattr(backup_service.pg_tools, "dump_database", lambda url, timeout=600: DUMP)
    monkeypatch.setattr("app.db.session.SessionLocal", session_factory)
    client = TestClient(app, base_url="https://localhost")
    try:
        yield {"client": client, "db": session_factory, "cfg": cfg}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def owner(client: TestClient, email: str = "owner@example.com") -> dict[str, str]:
    response = client.post("/auth/register", json={"email": email, "password": "Password123!", "full_name": "Backup Owner"})
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}


def actions(api) -> list[str]:
    with api["db"]() as db:
        return [row.action for row in db.scalars(select(AuditLog).where(AuditLog.resource_type == "backup")).all()]


def test_the_backup_routes_are_for_owners_and_admins_only(api):
    c = api["client"]
    headers = owner(c)
    viewer = owner(c, "viewer@example.com")
    with api["db"]() as db:
        user = db.scalar(select(User).where(User.email == "viewer@example.com"))
        db.add(UserTenantRole(user_id=user.id, tenant_id=headers["X-Tenant-ID"], role="viewer"))
        db.commit()
    as_viewer = {**viewer, "X-Tenant-ID": headers["X-Tenant-ID"]}
    for method, path in [("get", "/backups"), ("post", "/backups"), ("post", "/backups/key/show"), ("post", "/backups/restore"), ("get", "/backups/readiness")]:
        assert getattr(c, method)(path, headers=as_viewer).status_code == 403, path
    assert c.get("/backups").status_code in (401, 403)
    assert c.get("/backups/notice", headers=as_viewer).json() == {"notice": None}
    assert c.get("/backups/notice", headers=headers).json() == {"notice": "save-key"}


def test_back_up_now_download_and_the_key_shown_confirmed_and_audited(api):
    c = api["client"]
    headers = owner(c)
    status = c.get("/backups", headers=headers).json()
    assert status["sealed"] and status["sealedBy"] == "key" and status["backups"][0]["name"] == "hawk-ai-old.hkbackup" or status["backups"] == []
    assert status["separate"] is False and status["keep"] == 14 and status["encryption"]["notice"] == "save-key"
    made = c.post("/backups", json={}, headers=headers)
    assert made.status_code == 200, made.text
    name = made.json()["name"]
    got = c.get(f"/backups/{name}", headers=headers)
    assert got.status_code == 200 and archive.is_sealed(got.content) and name in got.headers["content-disposition"]
    assert c.get("/backups/..%2Fbackup-key.json", headers=headers).status_code == 404
    shown = c.post("/backups/key/show", headers=headers).json()
    assert canonical_backup_key(shown["key"]) == shown["key"] and shown["saved"] is False
    assert archive.read_backup(got.content, passphrase=shown["key"])
    confirmed = c.post("/backups/key/confirm", headers=headers).json()
    assert confirmed["encryption"]["keySaved"] and confirmed["encryption"]["notice"] is None
    assert c.post("/backups/encryption", json={"on": True}, headers=headers).status_code == 200
    assert actions(api) == ["backup.written", "backup.downloaded", "backup.key.shown", "backup.key.confirmed"]
    with api["db"]() as db:
        payloads = json.dumps([row.payload for row in db.scalars(select(AuditLog)).all()])
    assert shown["key"] not in payloads


def test_turning_encryption_on_for_an_installation_whose_backups_were_plain(api, monkeypatch):
    c = api["client"]
    headers = owner(c)
    (api["cfg"].data_dir / "backup-key.json").write_text(json.dumps({"version": 1, "mode": "plain", "decidedBy": "existing-installation"}))
    assert c.get("/backups", headers=headers).json()["encryption"]["canTurnOn"] is True
    assert c.post("/backups/key/show", headers=headers).status_code == 409
    assert c.post("/backups/encryption", json={"on": False}, headers=headers).status_code == 400
    turned = c.post("/backups/encryption", json={"on": True}, headers=headers).json()
    assert turned["encryption"]["source"] == "key" and turned["encryption"]["notice"] == "save-key"
    monkeypatch.setenv("BACKUP_PASSPHRASE", "env passphrase")
    assert c.post("/backups/encryption", json={"on": True}, headers=headers).status_code == 409
    assert c.get("/backups", headers=headers).json()["sealedBy"] == "environment"
    assert actions(api) == ["backup.encryption.on"]


def test_a_restore_from_the_page_is_checked_staged_and_cancelled(api):
    c = api["client"]
    headers = owner(c)
    other = generate_backup_key()
    buffer, _ = make(api["cfg"].data_dir, passphrase=other)
    asked = c.post("/backups/restore?check=1", content=buffer, headers=headers)
    assert asked.status_code == 400 and asked.json()["needsKey"] is True and "does not open it" in asked.json()["error"]
    checked = c.post("/backups/restore?check=1", content=buffer, headers={**headers, "X-Backup-Passphrase": other.lower()})
    assert checked.status_code == 200 and checked.json()["backup"]["hasDatabase"] and not (api["cfg"].data_dir / archive.PENDING_RESTORE).exists()
    staged = c.post("/backups/restore", content=buffer, headers={**headers, "X-Backup-Passphrase": other})
    assert staged.json()["staged"] and staged.json()["restartRequired"]
    assert archive.read_backup((api["cfg"].data_dir / archive.PENDING_RESTORE).read_bytes())  # staged decrypted
    assert c.get("/backups", headers=headers).json()["pendingRestore"] is True
    bad = c.post("/backups/restore", content=b"not a backup", headers=headers)
    assert bad.status_code == 400 and "Not a Hawk AI backup" in bad.json()["error"]
    assert c.delete("/backups/restore", headers=headers).json() == {"pendingRestore": False}
    assert actions(api) == ["backup.restore.staged", "backup.restore.refused", "backup.restore.cancelled"]


def test_a_restore_upload_may_be_up_to_200_mb_and_other_bodies_keep_their_limit(api, monkeypatch):
    from app.api.routers import backups as backups_router

    c = api["client"]
    headers = owner(c)
    big = b"x" * (3 * 1024 * 1024)  # over the 2 MB every other request is held to
    assert c.post("/backups/restore?check=1", content=big, headers=headers).status_code == 400  # read, not refused for size
    monkeypatch.setattr(backups_router, "MAX_RESTORE_UPLOAD_BYTES", 1024 * 1024)
    too = c.post("/backups/restore", content=big, headers=headers)
    assert too.status_code == 413 and "200 MB at most" in too.json()["error"]
    assert c.post("/https/inspect", content=big, headers={**headers, "Content-Type": "application/json"}).status_code == 413


def test_ready_for_production_checks_and_as_meant(api):
    c = api["client"]
    headers = owner(c)
    r = c.get("/backups/readiness", headers=headers).json()
    by = {x["id"]: x for x in r["checks"]}
    assert by["backup.sealed"]["state"] == "ok" and by["backup.separate"]["state"] == "todo" and by["people.admins"]["state"] == "todo"
    assert by["backup.restored"]["state"] == "note" and by["backup.restored"]["canAccept"]
    assert c.put("/backups/readiness/backup.restored", json={"accept": True}, headers=headers).json() == {"ok": True}
    again = {x["id"]: x for x in c.get("/backups/readiness", headers=headers).json()["checks"]}
    assert again["backup.restored"]["state"] == "ok" and again["backup.restored"]["accepted"]["by"] == "owner@example.com"
    assert c.put("/backups/readiness/backup.restored", json={"accept": False}, headers=headers).status_code == 200
    assert c.put("/backups/readiness/backup.sealed", json={"accept": True}, headers=headers).status_code == 404


# ---- pg_dump and pg_restore ----------------------------------------------------------------------------------------


def test_the_database_is_replaced_in_one_psql_transaction_without_what_postgres_16_does_not_know(tmp_path, monkeypatch):
    from app.services import pg_tools

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    seen = tmp_path / "psql-input.sql"
    args = tmp_path / "psql-args"
    (bin_dir / "pg_restore").write_text("#!/bin/sh\nif [ \"$1\" = --list ]; then exit 0; fi\nprintf 'SET statement_timeout = 0;\\nSET transaction_timeout = 0;\\nCREATE TABLE public.t (id int);\\n'\n")
    (bin_dir / "psql").write_text(f"#!/bin/sh\necho \"$@\" > {args}\necho \"$PGPASSWORD\" >> {args}\ncat > {seen}\n")
    for tool in bin_dir.iterdir():
        tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setattr(pg_tools, "_schemas", lambda url: ["audit", "public"])
    pg_tools.restore_database("postgresql+psycopg2://hawk:s3cret@db:5432/hawk", b"PGDMP")
    sql = seen.read_text()
    assert sql.startswith('DROP SCHEMA IF EXISTS "audit" CASCADE;\nDROP SCHEMA IF EXISTS "public" CASCADE;\nCREATE SCHEMA IF NOT EXISTS public;\n')
    assert "transaction_timeout" not in sql and "SET statement_timeout = 0;" in sql and "CREATE TABLE public.t" in sql
    called = args.read_text().splitlines()
    assert "--single-transaction" in called[0] and "ON_ERROR_STOP=1" in called[0] and "--dbname=hawk" in called[0]
    assert "s3cret" not in called[0] and called[1] == "s3cret"  # in the environment, never on the command line
    (bin_dir / "psql").write_text("#!/bin/sh\ncat > /dev/null\necho 'ERROR:  relation already exists' >&2\nexit 3\n")
    with pytest.raises(pg_tools.DatabaseToolError, match="the database is as it was: ERROR:  relation already exists"):
        pg_tools.restore_database("postgresql+psycopg2://hawk:s3cret@db:5432/hawk", b"PGDMP")


def test_the_instance_lock_is_postgres_only_and_a_missing_tool_is_said_plainly(monkeypatch, tmp_path):
    from app.services import pg_tools

    assert pg_tools.RestoreLock("sqlite+pysqlite:///:memory:").try_acquire() is True
    pg_tools.InstanceLock("sqlite+pysqlite:///:memory:", name="api").acquire().release()
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(pg_tools.DatabaseToolError, match="pg_dump is not installed"):
        pg_tools.dump_database("postgresql+psycopg2://hawk:x@db/hawk")
