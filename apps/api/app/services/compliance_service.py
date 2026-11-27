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
from sqlalchemy.exc import IntegrityError
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
        # Two requests on first load can both find no row: create it in a savepoint and, if the other request won,
        # read theirs instead of failing (and poisoning) this request's transaction.
        try:
            with db.begin_nested():
                row = CompliancePolicy(id=POLICY_ID)
                db.add(row)
                db.flush()
        except IntegrityError:
            row = db.get(CompliancePolicy, POLICY_ID, populate_existing=True)
            if row is None:
                raise
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


def controls(db: Session, *, time_view: dict[str, Any] | None = None, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Every control the software takes part in under DESC ISR / UAE IA / CERT-In, its status now and where its
    evidence is: read from the control registry (app/services/compliance_packs/controls.py), where each has its
    ``legacy_id`` (AC-01 … AI-01)."""

    from app.services.compliance_packs import controls as registry

    return registry.legacy_controls(registry.Context(db, tenant_id, time_view=time_view or time_status(db, ask_server=False)))


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
