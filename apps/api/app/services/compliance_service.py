"""Settings → Compliance (/settings/guide/compliance): how this installation stands against the controls a Dubai
government or semi-government entity applies under the Dubai Electronic Security Center's Information Security
Regulation (DESC ISR v3), the UAE Information Assurance Standard, and India's CERT-In directions of 28 April 2022.

What it does:
- keeps the compliance settings (compliance_policy, one row): how long the user activity and connector API activity
  are kept (never under MIN_RETENTION_DAYS; the audit log itself is never deleted), the data location statement and
  the incident contact;
- reads the clock's synchronisation from the kernel (adjtimex, read-only: no privilege needed) and, when
  TIME_SYNC_NTP_SERVER names one, asks that NTP server for the offset;
- lists each control the software takes part in, with its status worked out from the settings in force and a link
  to where it is shown or changed. "customer" controls depend on the server the customer runs (disk encryption, the
  host clock) and are shown with what the customer confirmed;
- builds the incident report: the security events of a time window, for a report to DESC (Dubai) or CERT-In (India,
  within 6 hours).

What it cannot do: the organisational controls (an ISMS, risk assessment, HR security, supplier management, the
incident response plan, business continuity) are the entity's and the vendor's own processes; the page says so.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import datetime as dt
import logging
import os
import socket
import struct
import sys
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings

logger = logging.getLogger(__name__)

POLICY_ID = 1
#: CERT-In's directions (iv): logs of ICT systems kept for a rolling 180 days.
MIN_RETENTION_DAYS = 180
MAX_RETENTION_DAYS = 3650
MAX_INCIDENT_ENTRIES = 10_000
#: The clock may be this far from the NTP server (or the database's clock) before it counts as out of sync.
MAX_SKEW_SECONDS = 1.0

STANDARDS = [
    {
        "key": "desc-isr",
        "name": "Dubai Information Security Regulation (DESC ISR) v3",
        "by": "Dubai Electronic Security Center",
        "applies": "Dubai government and semi-government entities, and through their contracts their suppliers and the systems they install.",
        "url": "https://www.desc.gov.ae/",
    },
    {
        "key": "uae-ias",
        "name": "UAE Information Assurance Standard",
        "by": "UAE Cyber Security Council (formerly TDRA / NESA)",
        "applies": "Federal entities and critical-sector entities across the UAE.",
        "url": "https://u.ae/en/information-and-services/justice-safety-and-the-law/cyber-safety-and-digital-security/uae-information-assurance-regulation",
    },
    {
        "key": "cert-in",
        "name": "CERT-In directions under section 70B(6) of the IT Act (28 April 2022)",
        "by": "Indian Computer Emergency Response Team",
        "applies": "Service providers, intermediaries, data centres, body corporates and government organisations in India.",
        "url": "https://www.cert-in.org.in/",
    },
    {
        "key": "dpdp",
        "name": "India's Digital Personal Data Protection Act 2023 and Rules 2025",
        "by": "Ministry of Electronics and Information Technology",
        "applies": "Anyone processing digital personal data in India (most obligations from May 2027).",
        "url": "https://www.meity.gov.in/",
    },
]


# ---- The settings ----------------------------------------------------------------------------------------------------


def policy(db: Session) -> Any:
    from app.db.models.access import CompliancePolicy

    row = db.get(CompliancePolicy, POLICY_ID)
    if row is None:
        row = CompliancePolicy(id=POLICY_ID)
        db.add(row)
        db.flush()
    return row


def _read_only(db: Session | None) -> Any:
    """The row when it exists, without creating it (for code paths that must not write)."""

    if db is None:
        return None
    from app.db.models.access import CompliancePolicy

    try:
        return db.get(CompliancePolicy, POLICY_ID)
    except Exception:  # noqa: BLE001 - a missing table (an old test database) means the defaults
        return None


def _days(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(MIN_RETENTION_DAYS, min(MAX_RETENTION_DAYS, number))


def activity_keep_days(db: Session | None) -> int:
    row = _read_only(db)
    return _days(row.activity_retention_days if row is not None else None, 365)


def connector_keep_days(db: Session | None) -> int:
    row = _read_only(db)
    return _days(row.connector_retention_days if row is not None else None, MIN_RETENTION_DAYS)


def data_location(db: Session | None) -> str:
    """The data location statement: what an administrator wrote, else DEPLOYMENT_DATA_LOCATION."""

    row = _read_only(db)
    written = str(row.data_location or "").strip() if row is not None else ""
    return written or str(settings.deployment_data_location or "").strip()


def settings_view(db: Session) -> dict[str, Any]:
    row = policy(db)
    return {
        "activityRetentionDays": activity_keep_days(db),
        "connectorRetentionDays": connector_keep_days(db),
        "minRetentionDays": MIN_RETENTION_DAYS,
        "maxRetentionDays": MAX_RETENTION_DAYS,
        "dataLocation": str(row.data_location or ""),
        "dataLocationDefault": str(settings.deployment_data_location or ""),
        "deploymentRegion": str(settings.deployment_region or ""),
        "incidentContact": str(row.incident_contact or ""),
    }


def clean_settings(body: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """The settings from the page: (values, "") or ({}, the sentence to show)."""

    out: dict[str, Any] = {}
    for key, column in (("activityRetentionDays", "activity_retention_days"), ("connectorRetentionDays", "connector_retention_days")):
        if key not in body:
            continue
        value = body.get(key)
        try:
            number = int(str(value).strip()) if not isinstance(value, bool) else -1
        except ValueError:
            number = -1
        if not MIN_RETENTION_DAYS <= number <= MAX_RETENTION_DAYS:
            return {}, f"Keep activity between {MIN_RETENTION_DAYS} days (CERT-In's minimum) and {MAX_RETENTION_DAYS} days."
        out[column] = number
    if "dataLocation" in body:
        text_value = " ".join(str(body.get("dataLocation") or "").split())
        if len(text_value) > 200:
            return {}, "The data location is at most 200 characters (for example: Dubai, United Arab Emirates — customer data centre)."
        out["data_location"] = text_value
    if "incidentContact" in body:
        text_value = " ".join(str(body.get("incidentContact") or "").split())
        if len(text_value) > 320:
            return {}, "The incident contact is at most 320 characters."
        out["incident_contact"] = text_value
    return out, ""


# ---- The clock -------------------------------------------------------------------------------------------------------


class _Timex(ctypes.Structure):
    # struct timex (linux/timex.h) on 64-bit Linux, with room to spare for the fields it may add.
    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time_sec", ctypes.c_long),
        ("time_usec", ctypes.c_long),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("_spare", ctypes.c_int * 16),
    ]


STA_UNSYNC = 0x0040
TIME_ERROR = 5


def kernel_clock() -> dict[str, Any]:
    """Is the host's clock disciplined by NTP (chrony, systemd-timesyncd, ntpd)? Read from the kernel with adjtimex
    (modes 0: reads only, needs no privilege, and a container shares the host's clock). {"synchronized": None} where
    it cannot be read (not Linux, or the call is blocked)."""

    if not sys.platform.startswith("linux"):
        return {"synchronized": None, "source": "kernel", "reason": "not Linux"}
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        timex = _Timex()
        state = libc.adjtimex(ctypes.byref(timex))
    except (OSError, AttributeError) as exc:
        return {"synchronized": None, "source": "kernel", "reason": type(exc).__name__}
    if state < 0:
        return {"synchronized": None, "source": "kernel", "reason": f"adjtimex errno {ctypes.get_errno()}"}
    synced = state != TIME_ERROR and not (timex.status & STA_UNSYNC)
    return {"synchronized": synced, "source": "kernel", "maxErrorMs": round(timex.maxerror / 1000, 1) if timex.maxerror >= 0 else None}


def ntp_offset(server: str, *, timeout: float = 2.0, port: int = 123) -> dict[str, Any]:
    """The offset of this clock from an NTP server (one SNTP request, RFC 4330): positive when this clock is behind."""

    packet = b"\x23" + 47 * b"\0"  # LI 0, version 4, mode 3 (client)
    ntp_epoch = 2_208_988_800
    try:
        address = socket.getaddrinfo(server, port, type=socket.SOCK_DGRAM)[0][4]
        with socket.socket(socket.AF_INET6 if ":" in address[0] else socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sent = time.time()
            sock.sendto(packet, address)
            data, _ = sock.recvfrom(512)
            received = time.time()
    except OSError as exc:
        return {"server": server, "ok": False, "reason": type(exc).__name__}
    if len(data) < 48 or data[1] == 0:
        return {"server": server, "ok": False, "reason": "no usable answer (stratum 0)"}
    rx_sec, rx_frac, tx_sec, tx_frac = struct.unpack("!IIII", data[32:48])
    server_rx = rx_sec - ntp_epoch + rx_frac / 2**32
    server_tx = tx_sec - ntp_epoch + tx_frac / 2**32
    offset = ((server_rx - sent) + (server_tx - received)) / 2
    return {"server": server, "ok": True, "offsetSeconds": round(offset, 3), "stratum": int(data[1])}


def database_skew(db: Session) -> float | None:
    """Seconds between the database's clock and this one (PostgreSQL only): the audit log's times come from both."""

    try:
        if db.get_bind().dialect.name != "postgresql":
            return None
        before = time.time()
        moment = db.scalar(select(func.now()))
        after = time.time()
    except Exception:  # noqa: BLE001 - a status, never an error
        return None
    if not isinstance(moment, dt.datetime):
        return None
    moment = moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)
    return round(moment.timestamp() - (before + after) / 2, 3)


def time_status(db: Session | None = None, *, ask_server: bool = True) -> dict[str, Any]:
    """The clock: synchronised or not (from the kernel, an NTP server when TIME_SYNC_NTP_SERVER is set, and the
    database's clock), with the time zone the schedules use."""

    kernel = kernel_clock()
    server = str(os.environ.get("TIME_SYNC_NTP_SERVER") or "").strip()
    ntp = ntp_offset(server) if server and ask_server else None
    skew = database_skew(db) if db is not None else None
    problems: list[str] = []
    if kernel["synchronized"] is False:
        problems.append("The server's clock is not synchronised by NTP (chrony or systemd-timesyncd on the host).")
    if ntp is not None and not ntp["ok"]:
        problems.append(f"The NTP server {server} did not answer ({ntp['reason']}).")
    if ntp is not None and ntp["ok"] and abs(ntp["offsetSeconds"]) > MAX_SKEW_SECONDS:
        problems.append(f"The clock is {abs(ntp['offsetSeconds'])} s from {server}.")
    if skew is not None and abs(skew) > MAX_SKEW_SECONDS:
        problems.append(f"The database's clock is {abs(skew)} s from the API's.")
    known = kernel["synchronized"] is not None or (ntp is not None and ntp["ok"])
    return {
        "synchronized": (not problems) if known else (False if problems else None),
        "kernel": kernel,
        "ntp": ntp,
        "ntpServer": server,
        "databaseSkewSeconds": skew,
        "timeZone": str(os.environ.get("TZ") or "UTC"),
        "utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "problems": problems,
    }


# ---- Encryption at rest --------------------------------------------------------------------------------------------


def encryption_status() -> dict[str, Any]:
    """What is encrypted at rest: backups (the backup key or BACKUP_PASSPHRASE), the secrets Hawk AI keeps in its
    database (always), and the disk itself (the customer's: DISK_ENCRYPTION_CONFIRMED says they confirmed it)."""

    backups: dict[str, Any]
    try:
        from app.services import backup_service

        status = backup_service.key_store().status()
        backups = {"encrypted": bool(status["encrypted"]), "source": status["source"], "optedOut": bool(status["optedOut"])}
    except Exception as exc:  # noqa: BLE001 - a status, never an error
        backups = {"encrypted": None, "source": "unknown", "reason": type(exc).__name__}
    return {
        "backups": backups,
        "secrets": {
            "encrypted": True,
            "what": "Two-step secrets, the email server's password and connector credentials are encrypted in the database; passwords are bcrypt hashes; recovery codes and uploaded sensitive values are kept only as hashes.",
        },
        "disk": {
            "confirmed": bool(settings.disk_encryption_confirmed),
            "what": "The database, backups and data folder sit on the customer's disk: full-disk or volume encryption (LUKS, BitLocker, the hypervisor's or the SAN's) is the customer's. DISK_ENCRYPTION_CONFIRMED=true records that it is on.",
        },
    }


# ---- The controls ----------------------------------------------------------------------------------------------------


def _control(cid: str, title: str, refs: list[str], status: str, detail: str, owner: str, href: str, label: str) -> dict[str, Any]:
    return {"id": cid, "title": title, "refs": refs, "status": status, "detail": detail, "owner": owner, "evidence": {"href": href, "label": label}}


def _https_view() -> dict[str, Any]:
    try:
        from app.services import https_runtime

        manager = https_runtime.manager()
        return {"mode": manager.mode, "minVersion": str(manager.state.get("minVersion") or "TLSv1.2")}
    except Exception as exc:  # noqa: BLE001
        return {"mode": "unknown", "minVersion": "", "reason": type(exc).__name__}


def _integrity_state() -> str:
    try:
        from app.services.integrity.service import IntegrityService

        last = IntegrityService().last
    except Exception:  # noqa: BLE001
        return "unknown"
    return str((last or {}).get("state") or "unknown")


def controls(db: Session, *, time_view: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every control the software takes part in, its status now and where its evidence is."""

    from app.services import account_security, password_policy

    sign_in = account_security.policy(db)
    rule = password_policy.rule(db)
    base = password_policy.BASELINE
    idle = account_security.idle_minutes(db)
    sso_only = bool(settings.company_sso_enabled and sign_in.sso_password_admins_only)
    time_view = time_view or time_status(db, ask_server=False)
    enc = encryption_status()
    https = _https_view()
    integrity = _integrity_state()
    row = policy(db)
    out: list[dict[str, Any]] = []

    strong = rule.min_length >= base["minLength"] and rule.classes >= base["classes"] and rule.history >= base["history"] and 0 < rule.max_age_days <= base["maxAgeDays"]
    out.append(_control(
        "AC-01", "Password rule", ["DESC ISR: Access Control", "UAE IAS: T5 Access control"],
        "met" if strong else "action",
        f"In force: {password_policy.describe(rule)}." + ("" if strong else " Apply the recommended baseline or set your entity's own rule."),
        "administrator", "/settings/signin", "Settings → Sign-in",
    ))
    out.append(_control(
        "AC-02", "Two-step sign-in or company single sign-on", ["DESC ISR: Access Control", "UAE IAS: T5 Access control"],
        "met" if (sign_in.two_step_required or sso_only) else "action",
        "Required for everyone who signs in with a password." if sign_in.two_step_required else ("Single sign-on only (passwords for Admins)." if sso_only else "Each person chooses: require two-step sign-in, or use single sign-on with passwords for Admins only."),
        "administrator", "/settings/signin", "Settings → Sign-in",
    ))
    out.append(_control(
        "AC-03", "Lock after wrong passwords; limit per address", ["DESC ISR: Access Control", "UAE IAS: T5 Access control"],
        "met", f"{account_security.MAX_FAILED} wrong passwords or codes lock the account for {account_security.LOCK_SECONDS // 60} minutes; at most {account_security.SIGN_IN_LIMIT} attempts per {account_security.SIGN_IN_WINDOW_SECONDS // 60} minutes from one address.",
        "product", "/settings/signin", "Settings → Sign-in",
    ))
    out.append(_control(
        "AC-04", "Idle sign-out", ["DESC ISR: Access Control", "UAE IAS: T5 Access control"],
        "met" if idle <= base["sessionIdleMinutes"] else ("partial" if idle <= 30 else "action"),
        f"Signed out after {idle} minutes without activity." + ("" if idle <= base["sessionIdleMinutes"] else f" The recommended baseline is {base['sessionIdleMinutes']} minutes."),
        "administrator", "/settings/signin", "Settings → Sign-in",
    ))
    out.append(_control(
        "AC-05", "Notice before sign-in", ["DESC ISR: Access Control", "UAE IAS: T5 Access control"],
        "met" if (sign_in.banner_text or "").strip() else "action",
        "Shown on the sign-in page." if (sign_in.banner_text or "").strip() else "No notice yet: write the authorised-use and monitoring notice your entity requires.",
        "administrator", "/settings/signin", "Settings → Sign-in",
    ))
    out.append(_control(
        "AC-06", "Roles and least privilege", ["DESC ISR: Access Control", "UAE IAS: T5 Access control"],
        "met", "People, teams and roles with per-permission grants; nobody gives more than they hold; there is always an active Owner; every change is in the audit log.",
        "product", "/settings/roles", "Settings → Roles & permissions",
    ))
    out.append(_control(
        "LG-01", "Tamper-evident audit log", ["DESC ISR: Operations, Systems and Communications Management", "UAE IAS: T3 Operations management"],
        "met", "Every entry is chained with an HMAC; entries are never updated or deleted; the chain can be checked from the page and exported with a signature.",
        "product", "/settings/audit", "Settings → Audit log (Verify)",
    ))
    keep_ok = activity_keep_days(db) >= MIN_RETENTION_DAYS and connector_keep_days(db) >= MIN_RETENTION_DAYS
    out.append(_control(
        "LG-02", "Log retention (180 days at least)", ["CERT-In direction (iv)", "DESC ISR: Compliance and Audit", "DPDP Rules: one-year logs"],
        "met" if keep_ok else "action",
        f"Audit log: kept for good. User activity: {activity_keep_days(db)} days. Connector API activity: {connector_keep_days(db)} days. The services' own log lines are kept by Docker by size: forward them to your SIEM to keep them longer.",
        "product", "/settings/compliance", "Settings → Compliance",
    ))
    synced = time_view.get("synchronized")
    out.append(_control(
        "LG-03", "Clock synchronised (NTP)", ["CERT-In direction (i)", "DESC ISR: Operations, Systems and Communications Management"],
        "met" if synced else ("action" if synced is False else "customer"),
        "Synchronised." if synced else ("; ".join(time_view.get("problems") or []) or "Could not be read here: confirm that the host runs chrony or systemd-timesyncd (in India, against NIC or NPL servers)."),
        "customer", "/settings/compliance", "Settings → Compliance (Clock)",
    ))
    out.append(_control(
        "LG-04", "Security events to a SIEM", ["DESC ISR: Incident and Problem Management", "UAE IAS: T3 Operations management"],
        "partial",
        "The audit log exports as CEF (ArcSight, QRadar, Sentinel, Splunk), CSV or signed JSON Lines for any time window; the services write JSON log lines a syslog or Docker logging driver can forward. A built-in continuous syslog sender is not there yet.",
        "product", "/settings/audit", "Settings → Audit log (Export)",
    ))
    out.append(_control(
        "IR-01", "Incident report (DESC, CERT-In within 6 hours)", ["CERT-In direction (ii), (iii)", "DESC ISR: Incident and Problem Management", "UAE IAS: T8 Incident management"],
        "met" if (row.incident_contact or "").strip() else "action",
        "The incident report gathers a time window's security events, the clock and the installation's identity, signed." + ("" if (row.incident_contact or "").strip() else " Name the incident contact (CERT-In's point of contact) first."),
        "administrator", "/settings/compliance", "Settings → Compliance (Incident report)",
    ))
    mode = https["mode"]
    out.append(_control(
        "CR-01", "Encryption in transit", ["DESC ISR: Operations, Systems and Communications Management", "UAE IAS: T4 Communications"],
        "met" if mode == "on" and https.get("minVersion") in ("TLSv1.2", "TLSv1.3") else "action",
        f"HTTPS: {mode}; at least {https.get('minVersion') or 'TLS 1.2'}." + ("" if mode == "on" else " Choose HTTPS only."),
        "administrator", "/settings/https", "Settings → HTTPS",
    ))
    backups = enc["backups"]
    out.append(_control(
        "CR-02", "Backups encrypted", ["DESC ISR: Business Continuity Planning", "UAE IAS: T9 Continuity"],
        "met" if backups.get("encrypted") else "action",
        "Every backup is encrypted (" + ("BACKUP_PASSPHRASE" if backups.get("source") == "passphrase" else "this server's backup key") + ")." if backups.get("encrypted") else "Backups are plain: turn encryption on.",
        "administrator", "/settings/backups", "Settings → Backups & health",
    ))
    out.append(_control(
        "CR-03", "Disk encrypted at rest", ["DESC ISR: Information and Information Assets Management", "UAE IAS: T1 Asset management"],
        "met" if enc["disk"]["confirmed"] else "customer",
        "The customer confirmed full-disk encryption (DISK_ENCRYPTION_CONFIRMED)." if enc["disk"]["confirmed"] else enc["disk"]["what"],
        "customer", "/settings/compliance", "Settings → Compliance (Encryption)",
    ))
    out.append(_control(
        "SI-01", "Genuine, signed software", ["DESC ISR: Information Systems Acquisition, Development and Management", "UAE IAS: T7 Acquisition, development and maintenance"],
        "met" if integrity == "genuine" else ("action" if integrity in ("tampered", "not-genuine") else "partial"),
        f"Last check: {integrity}. Images are built and signed by the release workflow; files are checked at start and every few hours; updates roll back by themselves.",
        "product", "/settings/updates", "Settings → Updates",
    ))
    location = data_location(db)
    resident = bool(location) and location not in ("local-development", "on-premise")
    out.append(_control(
        "DR-01", "Data residency statement", ["DESC ISR: Cloud Security (data residency)", "UAE PDPL", "CERT-In direction (iv)"],
        "met" if resident else "action",
        f"Data location: {location or 'not stated'}. Hawk AI stores and processes everything on this server; nothing is sent to the vendor." + ("" if resident else " State where this server is (city and country)."),
        "administrator", "/settings/compliance", "Settings → Compliance",
    ))
    out.append(_control(
        "AI-01", "AI use controls (sensitive data, prompt attacks)", ["Dubai AI Security Policy", "UAE National AI Security Policy"],
        "met", "Sensitive data and prompt-injection checks run on this server, with no outside AI service, in the LLM and MCP gateways, the browser extension and the desktop guard.",
        "product", "/settings/guide/compliance", "Guide → Compliance",
    ))
    return out


def summary(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"met": 0, "partial": 0, "action": 0, "customer": 0}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return counts


# ---- The incident report -------------------------------------------------------------------------------------------

#: Kinds of event an incident report counts, by the start of the audit action.
EVENT_KINDS = {
    "signInRefused": ("auth.sign_in.refused",),
    "twoStep": ("auth.two_step",),
    "passwordResets": ("auth.password_reset", "auth.password"),
    "peopleAndRoles": ("iam.", "user.", "ai_iam.", "role"),
    "settings": ("settings.", "auth.sign_in_policy", "https.", "compliance."),
    "backupsAndRestores": ("backup.", "restore."),
    "updatesAndIntegrity": ("update", "integrity"),
    "gatewayDecisions": ("gateway.", "llm_gateway.", "executive_mcp.", "extension.", "endpoint."),
    "auditAccess": ("audit.",),
}


def _kind(action: str) -> str:
    for kind, prefixes in EVENT_KINDS.items():
        if any(action.startswith(p) for p in prefixes):
            return kind
    return "other"


def incident_report(db: Session, *, tenant_id: str, since: dt.datetime, until: dt.datetime, generated_by: str) -> dict[str, Any]:
    """A time window's security events for a report to DESC or CERT-In: the installation, the clock, counts by kind,
    every audit entry in the window (with its sequence number and MAC, so it can be checked against the chain), and
    the fields CERT-In's incident form asks for, filled where Hawk AI knows them."""

    from app.db.models.audit import AuditLog
    from app.services import audit_chain
    from app.version import APP_VERSION

    row = policy(db)
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id, AuditLog.created_at >= since, AuditLog.created_at <= until)
        .order_by(AuditLog.created_at, AuditLog.seq)
        .limit(MAX_INCIDENT_ENTRIES + 1)
    ).all()
    counts: dict[str, int] = {}
    entries = []
    for entry in rows[:MAX_INCIDENT_ENTRIES]:
        action = str(entry.action)
        kind = _kind(action)
        counts[kind] = counts.get(kind, 0) + 1
        payload = entry.payload if isinstance(entry.payload, dict) else {}
        locked = "Account locked" in str(payload.get("reason") or "")
        if locked:
            counts["accountsLocked"] = counts.get("accountsLocked", 0) + 1
        entries.append({
            "at": audit_chain.iso(entry.created_at),
            "seq": entry.seq,
            "mac": entry.mac,
            "action": action,
            "kind": kind,
            "actorType": entry.actor_type,
            "actorUserId": entry.actor_user_id,
            "target": f"{entry.resource_type} {entry.resource_id}".strip(),
            "ip": str(payload.get("ip") or ""),
            "reason": str(payload.get("reason") or "")[:500],
            "outcome": str(payload.get("outcome") or ""),
        })
    clock = time_status(db)
    location = data_location(db)
    return {
        "kind": "hawk-ai-incident-report",
        "version": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "generatedBy": generated_by,
        "window": {"from": since.isoformat().replace("+00:00", "Z"), "to": until.isoformat().replace("+00:00", "Z")},
        "installation": {
            "product": "Hawk AI",
            "version": APP_VERSION,
            "deploymentId": str(settings.deployment_id or ""),
            "region": str(settings.deployment_region or ""),
            "dataLocation": location,
            "contact": str(row.incident_contact or ""),
        },
        "clock": clock,
        "counts": dict(sorted(counts.items())),
        "truncated": len(rows) > MAX_INCIDENT_ENTRIES,
        "entries": entries,
        "reporting": {
            "certIn": {
                "deadline": "Report to CERT-In within 6 hours of noticing the incident (incident@cert-in.org.in; the form and the list of reportable incidents are on cert-in.org.in).",
                "fields": {
                    "organisation": "",
                    "pointOfContact": str(row.incident_contact or ""),
                    "timeOfOccurrence": "",
                    "timeNoticed": "",
                    "incidentType": "",
                    "systemsAffected": f"Hawk AI {APP_VERSION} ({location or 'location not stated'})",
                    "description": "",
                    "actionsTaken": "",
                },
            },
            "desc": {
                "note": "Dubai government entities report information security incidents to DESC as their incident response procedure under the ISR sets out; attach this file.",
            },
        },
        "check": "Each entry carries its sequence number and MAC: compare with the audit log's chain (Settings → Audit log → Verify). The file itself carries an evidence signature (X-Hawk-Evidence-Signature), checkable offline with tools/verify_evidence.py.",
    }


# ---- CEF (ArcSight Common Event Format) for SIEMs ------------------------------------------------------------------


def _cef_header(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def cef_severity(action: str, refused: bool) -> int:
    if "locked" in action or action.startswith(("integrity", "audit.verify")):
        return 8 if refused else 5
    if refused:
        return 6
    if action.startswith(("auth.sign_in_policy", "iam.", "settings.", "https.", "backup.", "restore.", "update")):
        return 4
    return 3


def cef_line(event: dict[str, Any], *, version: str) -> str:
    """One audit entry as a CEF line (CEF:0|vendor|product|version|signature|name|severity|extension)."""

    action = str(event.get("action") or "")
    refused = action.startswith("refused") or "refused" in action
    details = event.get("details") or {}
    actor = event.get("actor") or {}
    at = str(event.get("at") or "")
    try:
        rt = int(dt.datetime.fromisoformat(at.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        rt = 0
    extension = {
        "rt": rt,
        "act": action,
        "suser": actor.get("email") or "",
        "src": event.get("ip") or "",
        "outcome": "failure" if refused else "success",
        "cs1Label": "seq",
        "cs1": event.get("seq") if event.get("seq") is not None else "",
        "cs2Label": "mac",
        "cs2": event.get("mac") or "",
        "cs3Label": "target",
        "cs3": event.get("target") or "",
        "msg": str(details.get("reason") or "")[:1000],
        "externalId": event.get("id") or "",
    }
    head = "|".join(_cef_header(v) for v in ("CEF:0", "Hawk AI", "Hawk AI", version, action[:100], (str(details.get("reason") or action))[:200], cef_severity(action, refused)))
    return head + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in extension.items() if v != "")
