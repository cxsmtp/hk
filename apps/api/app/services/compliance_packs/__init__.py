"""Framework packs (Settings → Compliance, /settings/guide/compliance): for each framework a customer has to meet, its
requirements, which Hawk AI controls (controls.py) support each one, their live status, and a signed evidence bundle
(evidence.py).

A pack is a versioned data file in packs/ (JSON), checked against SCHEMA when it is read:

    {"id", "version", "order", "optional", "framework": {"name", "short", "version", "publisher", "jurisdiction", "url"},
     "summary", "scope", "sources": [{"title", "url"}], "notes": [{"id", "title", "text"}],
     "requirements": [{"id", "title", "applicability", "controls": [control ids], "evidence": [evidence sources],
                       "note"?}]}

- ``id`` of a requirement is the framework's own reference (an article, a clause, a control number). ``title`` is our
  own short wording: never the standard's text (ISO, PCI SSC and NCA texts are copyrighted).
- ``applicability``: ``product`` (Hawk AI does it, as software), ``customer`` (the customer does it with Hawk AI or
  around it: the server, settings, how AI is used) or ``organisational`` (a process, a policy, people: Hawk AI can only
  hold the evidence). A product requirement always maps to at least one control.
- ``evidence``: what the evidence bundle carries for it (EVIDENCE_SOURCES).

What a requirement's status means:

- ``met`` / ``partly`` / ``gap``: from its controls (``not_applicable`` controls left out): all met, some, none;
- ``not_applicable``: an owner or admin recorded it as out of scope (with the reason), or every control is;
- ``attested``: no control of Hawk AI covers it, and an owner or admin recorded that it is in place (where its evidence
  is), within the last year;
- ``yours``: no control of Hawk AI covers it and nothing is recorded: the organisation's own process.

A pack supports compliance work: it never makes the customer compliant or certified by itself, and the page says so.
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.services.compliance_packs import controls as registry

PACKS_DIR = Path(__file__).resolve().parent / "packs"
APPLICABILITY = ("product", "customer", "organisational")
REQUIREMENT_STATUSES = ("met", "partly", "gap", "not_applicable", "attested", "yours")
ATTESTATION_STATUSES = ("in_place", "not_applicable")
ATTESTATION_DAYS = 365
MAX_NOTE = 2000
MAX_REFERENCE = 500
DISCLAIMER = (
    "Packs support your compliance work: they show where Hawk AI's controls stand against a framework and gather signed "
    "evidence. They do not by themselves make your organisation compliant or certified; your auditor or regulator decides that."
)
#: What a requirement's evidence can name: a kind of record the evidence bundle carries.
EVIDENCE_SOURCES = {
    "audit:sign_in": ("auth.",),
    "audit:people": ("iam.", "user.", "ai_iam.", "role"),
    "audit:settings": ("settings.", "auth.sign_in_policy", "https.", "compliance.", "detection.", "policies."),
    "audit:backups": ("backup.", "restore."),
    "audit:updates": ("update", "integrity", "self_recovery", "system."),
    "audit:gateway": ("gateway.", "llm_gateway.", "executive_mcp.", "extension.", "endpoint."),
    "audit:approvals": ("ai_system", "approval"),
    "audit:audit": ("audit.",),
    "audit:terms": ("terms.",),
    "settings:sign_in": (),
    "settings:compliance": (),
    "settings:detection": (),
    "settings:approvals": (),
    "settings:encryption": (),
    "records:terms": (),
    "records:approvals": (),
    "records:ai_inventory": (),
    "records:attestations": (),
    "records:operations": (),
    "records:detector_coverage": (),
}
_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,47}$")
_REQ_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .:()/_\-]{0,63}$")
_URL = re.compile(r"^https://[^\s]+$")


class PackError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---- Reading and checking the pack files ----------------------------------------------------------------------------


def _text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) <= limit


def validate(pack: Any, *, name: str = "pack") -> list[str]:
    """Every problem with a pack definition (empty when it is sound)."""

    problems: list[str] = []
    if not isinstance(pack, dict):
        return [f"{name}: not an object"]
    allowed = {"id", "version", "order", "optional", "framework", "summary", "scope", "sources", "notes", "requirements"}
    for key in sorted(set(pack) - allowed):
        problems.append(f"{name}: unknown key {key!r}")
    if not isinstance(pack.get("id"), str) or not _PACK_ID.match(pack["id"]):
        problems.append(f"{name}: id must be lower-case letters, digits and hyphens")
    if not isinstance(pack.get("version"), str) or not re.match(r"^\d{4}\.\d{2}\.\d+$", pack["version"]):
        problems.append(f"{name}: version must be YYYY.MM.N")
    if not isinstance(pack.get("order"), int) or isinstance(pack.get("order"), bool):
        problems.append(f"{name}: order must be a whole number")
    if not isinstance(pack.get("optional"), bool):
        problems.append(f"{name}: optional must be true or false")
    framework = pack.get("framework")
    if not isinstance(framework, dict):
        problems.append(f"{name}: framework must be an object")
    else:
        for key in ("name", "short", "version", "publisher", "jurisdiction"):
            if not _text(framework.get(key), 200):
                problems.append(f"{name}: framework.{key} is required")
        if not isinstance(framework.get("url"), str) or not _URL.match(framework["url"]):
            problems.append(f"{name}: framework.url must be an https address")
    for key, limit in (("summary", 1200), ("scope", 1200)):
        if not _text(pack.get(key), limit):
            problems.append(f"{name}: {key} is required (at most {limit} characters)")
    sources = pack.get("sources")
    if not isinstance(sources, list) or not sources:
        problems.append(f"{name}: sources must list where the requirement ids were checked")
    else:
        for index, source in enumerate(sources):
            if not isinstance(source, dict) or not _text(source.get("title"), 300) or not _URL.match(str(source.get("url") or "")):
                problems.append(f"{name}: sources[{index}] needs a title and an https url")
    notes = pack.get("notes", [])
    if not isinstance(notes, list):
        problems.append(f"{name}: notes must be a list")
    else:
        for index, note in enumerate(notes):
            if not isinstance(note, dict) or not _text(note.get("id"), 64) or not _text(note.get("title"), 200) or not _text(note.get("text"), 2000):
                problems.append(f"{name}: notes[{index}] needs an id, a title and a text")
    requirements = pack.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        problems.append(f"{name}: requirements must be a non-empty list")
        return problems
    seen: set[str] = set()
    for index, req in enumerate(requirements):
        where = f"{name}: requirements[{index}]"
        if not isinstance(req, dict):
            problems.append(f"{where}: not an object")
            continue
        for key in sorted(set(req) - {"id", "title", "applicability", "controls", "evidence", "note"}):
            problems.append(f"{where}: unknown key {key!r}")
        rid = req.get("id")
        if not isinstance(rid, str) or not _REQ_ID.match(rid):
            problems.append(f"{where}: id {rid!r} is not a framework reference")
        elif rid in seen:
            problems.append(f"{where}: id {rid} repeats")
        else:
            seen.add(rid)
            where = f"{name}: {rid}"
        if not _text(req.get("title"), 160):
            problems.append(f"{where}: title is required (at most 160 characters, in our own words)")
        if req.get("applicability") not in APPLICABILITY:
            problems.append(f"{where}: applicability must be one of {', '.join(APPLICABILITY)}")
        mapped = req.get("controls")
        if not isinstance(mapped, list) or any(not isinstance(c, str) for c in mapped):
            problems.append(f"{where}: controls must be a list of control ids")
            mapped = []
        for ref in mapped:
            if not registry.exists(ref):
                problems.append(f"{where}: control {ref!r} is not in the control registry")
        if len(set(mapped)) != len(mapped):
            problems.append(f"{where}: a control is listed twice")
        if not mapped and req.get("applicability") == "product":
            problems.append(f"{where}: a product requirement must map to at least one control")
        evidence = req.get("evidence")
        if not isinstance(evidence, list) or not evidence or any(e not in EVIDENCE_SOURCES for e in evidence):
            problems.append(f"{where}: evidence must list sources from {', '.join(sorted(EVIDENCE_SOURCES))}")
        if "note" in req and not _text(req.get("note"), 600):
            problems.append(f"{where}: note must be text of at most 600 characters")
    return problems


@functools.lru_cache(maxsize=1)
def _load() -> tuple[dict[str, Any], ...]:
    packs = []
    for path in sorted(PACKS_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        problems = validate(data, name=path.name)
        if problems:
            raise PackError(f"Pack {path.name} is not valid: " + "; ".join(problems[:5]), 500)
        if path.stem != data["id"]:
            raise PackError(f"Pack {path.name} must be named after its id ({data['id']}.json).", 500)
        packs.append(data)
    packs.sort(key=lambda p: (p["order"], p["id"]))
    return tuple(packs)


def packs() -> tuple[dict[str, Any], ...]:
    return _load()


def pack(pack_id: str) -> dict[str, Any]:
    for item in packs():
        if item["id"] == pack_id:
            return item
    raise PackError("No such pack.", 404)


def requirement(pack_def: dict[str, Any], requirement_id: str) -> dict[str, Any]:
    for item in pack_def["requirements"]:
        if item["id"] == requirement_id:
            return item
    raise PackError("No such requirement in this pack.", 404)


# ---- Attestations ---------------------------------------------------------------------------------------------------


def attestations(db: Session, tenant_id: str, pack_id: str | None = None) -> dict[tuple[str, str], Any]:
    from app.db.models.access import ComplianceAttestation

    query = select(ComplianceAttestation).where(ComplianceAttestation.tenant_id == tenant_id)
    if pack_id:
        query = query.where(ComplianceAttestation.pack_id == pack_id)
    try:
        rows = db.scalars(query).all()
    except Exception:  # noqa: BLE001 - a database before migration 0105: nothing recorded
        return {}
    return {(r.pack_id, r.requirement_id): r for r in rows}


def _utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, dt.datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def attestation_view(row: Any, now: dt.datetime) -> dict[str, Any]:
    expires = _utc(row.expires_at)
    return {
        "status": row.status,
        "note": row.note or "",
        "reference": row.reference or "",
        "by": row.attested_by_email or "",
        "at": _utc(row.attested_at).isoformat() if _utc(row.attested_at) else None,
        "expiresAt": expires.isoformat() if expires else None,
        "current": expires is None or expires > now,
    }


def clean_attestation(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise PackError("Send status, note and reference.")
    status = body.get("status")
    if status not in ATTESTATION_STATUSES:
        raise PackError("Status is in_place or not_applicable.")
    note = " ".join(str(body.get("note") or "").split())
    reference = " ".join(str(body.get("reference") or "").split())
    if not note:
        raise PackError("Say what is in place and where its evidence is, or why it does not apply." if status == "in_place" else "Say why it does not apply.")
    if len(note) > MAX_NOTE or len(reference) > MAX_REFERENCE:
        raise PackError(f"The note is at most {MAX_NOTE} characters and the reference at most {MAX_REFERENCE}.")
    days = body.get("reviewDays", ATTESTATION_DAYS)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= ATTESTATION_DAYS:
        raise PackError(f"Review it within 1 to {ATTESTATION_DAYS} days.")
    return {"status": status, "note": note, "reference": reference, "days": days}


def save_attestation(db: Session, *, tenant_id: str, pack_id: str, requirement_id: str, body: Any, user_id: str | None, email: str, now: dt.datetime | None = None) -> tuple[Any, str]:
    """Record (or replace) what an owner or admin says about one requirement. Returns (row, what changed in words)."""

    from app.db.models.access import ComplianceAttestation

    pack_def = pack(pack_id)
    requirement(pack_def, requirement_id)
    values = clean_attestation(body)
    now = now or dt.datetime.now(dt.timezone.utc)
    row = attestations(db, tenant_id, pack_id).get((pack_id, requirement_id))
    before = row.status if row is not None else "nothing"
    if row is None:
        row = ComplianceAttestation(tenant_id=tenant_id, pack_id=pack_id, requirement_id=requirement_id)
        db.add(row)
    row.status = values["status"]
    row.note = values["note"]
    row.reference = values["reference"]
    row.attested_by = user_id
    row.attested_by_email = email or ""
    row.attested_at = now
    row.expires_at = now + dt.timedelta(days=values["days"])
    db.flush()
    words = {"in_place": "in place", "not_applicable": "not applicable", "nothing": "nothing recorded"}
    return row, f"{pack_def['framework']['short']} {requirement_id}: {words[before]} → {words[row.status]} ({values['note'][:200]})."


def delete_attestation(db: Session, *, tenant_id: str, pack_id: str, requirement_id: str) -> str:
    pack_def = pack(pack_id)
    requirement(pack_def, requirement_id)
    row = attestations(db, tenant_id, pack_id).get((pack_id, requirement_id))
    if row is None:
        raise PackError("Nothing is recorded for this requirement.", 404)
    db.delete(row)
    db.flush()
    return f"{pack_def['framework']['short']} {requirement_id}: record removed."


# ---- Status ---------------------------------------------------------------------------------------------------------


def requirement_status(req: dict[str, Any], results: list[dict[str, Any]], attestation: dict[str, Any] | None) -> tuple[str, str]:
    """(status, why) of one requirement from its controls' results and what was recorded."""

    if attestation and attestation["current"] and attestation["status"] == "not_applicable":
        return "not_applicable", f"Recorded as not applicable by {attestation['by'] or 'an administrator'}: {attestation['note']}"
    if results:
        counted = [r for r in results if r["status"] != registry.NA]
        if not counted:
            return "not_applicable", "None of its controls applies here."
        met = sum(1 for r in counted if r["status"] == registry.MET)
        some = sum(1 for r in counted if r["status"] in (registry.MET, registry.PARTLY))
        if met == len(counted):
            return "met", "Every control that supports it is met."
        if some:
            return "partly", f"{met} of {len(counted)} supporting controls met; see each control."
        return "gap", "None of its supporting controls is in force yet."
    if attestation and attestation["current"]:
        return "attested", f"Recorded as in place by {attestation['by'] or 'an administrator'}: {attestation['note']}"
    if attestation:
        return "yours", "The record of it is due for review."
    return "yours", "Your organisation's own process: Hawk AI cannot check it. Record where its evidence is."


def summarise(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {s: 0 for s in REQUIREMENT_STATUSES}
    by_applicability: dict[str, dict[str, int]] = {a: {"total": 0, **{s: 0 for s in REQUIREMENT_STATUSES}} for a in APPLICABILITY}
    for item in items:
        counts[item["status"]] += 1
        by_applicability[item["applicability"]]["total"] += 1
        by_applicability[item["applicability"]][item["status"]] += 1
    return {"total": len(items), **counts, "byApplicability": by_applicability}


def evaluate_pack(db: Session, tenant_id: str, pack_id: str, *, evaluator: registry.Evaluator | None = None, now: dt.datetime | None = None) -> dict[str, Any]:
    """The pack with each requirement's status now, its controls' results and what was recorded about it."""

    pack_def = pack(pack_id)
    now = now or dt.datetime.now(dt.timezone.utc)
    evaluator = evaluator or registry.Evaluator(registry.Context(db, tenant_id, now=now))
    recorded = attestations(db, tenant_id, pack_id)
    items = []
    for req in pack_def["requirements"]:
        results = [evaluator(ref) for ref in req["controls"]]
        row = recorded.get((pack_id, req["id"]))
        attestation = attestation_view(row, now) if row is not None else None
        status, why = requirement_status(req, results, attestation)
        items.append({
            "id": req["id"],
            "title": req["title"],
            "applicability": req["applicability"],
            "status": status,
            "why": why,
            "note": req.get("note", ""),
            "controls": [{k: r[k] for k in ("id", "title", "status", "reason", "scope", "href", "label", "planned")} for r in results],
            "evidence": list(req["evidence"]),
            "attestation": attestation,
        })
    return {
        **{k: pack_def[k] for k in ("id", "version", "optional", "framework", "summary", "scope", "sources")},
        "notes": pack_def.get("notes", []),
        "summary": summarise(items),
        "requirements": items,
        "disclaimer": DISCLAIMER,
        "evaluatedAt": now.isoformat().replace("+00:00", "Z"),
    }


def overview(db: Session, tenant_id: str) -> dict[str, Any]:
    """Every pack with its counts (one evaluation of each control, shared across packs)."""

    now = dt.datetime.now(dt.timezone.utc)
    evaluator = registry.Evaluator(registry.Context(db, tenant_id, now=now))
    out = []
    for pack_def in packs():
        view = evaluate_pack(db, tenant_id, pack_def["id"], evaluator=evaluator, now=now)
        out.append({**{k: pack_def[k] for k in ("id", "version", "optional", "framework", "summary")}, "counts": view["summary"]})
    return {"packs": out, "disclaimer": DISCLAIMER, "evaluatedAt": now.isoformat().replace("+00:00", "Z")}


def control_registry(db: Session, tenant_id: str) -> dict[str, Any]:
    """Every control with its status now (parameterised ones as the packs use them), and which packs use each."""

    evaluator = registry.Evaluator(registry.Context(db, tenant_id))
    used: dict[str, list[str]] = {}
    for pack_def in packs():
        for req in pack_def["requirements"]:
            for ref in req["controls"]:
                used.setdefault(ref, [])
                if pack_def["id"] not in used[ref]:
                    used[ref].append(pack_def["id"])
    refs = [c.id for c in registry.CONTROLS if c.param_check is None] + sorted(r for r in used if registry.BY_ID[registry.split(r)[0]].param_check is not None)
    return {"controls": [{**evaluator(ref), "packs": used.get(ref, [])} for ref in refs]}


__all__ = [
    "APPLICABILITY",
    "ATTESTATION_STATUSES",
    "DISCLAIMER",
    "EVIDENCE_SOURCES",
    "PackError",
    "REQUIREMENT_STATUSES",
    "attestations",
    "control_registry",
    "delete_attestation",
    "evaluate_pack",
    "overview",
    "pack",
    "packs",
    "requirement_status",
    "save_attestation",
    "validate",
]
