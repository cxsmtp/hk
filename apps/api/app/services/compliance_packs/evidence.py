"""The signed evidence bundle of a framework pack (Settings → Compliance → Download signed evidence).

One zip, every file at its top level:

- ``manifest.json``: ``hawk-evidence-manifest/v1``: the pack, the window, who made it, and every other file by name
  and SHA-256, signed inside with the installation's evidence key (app/services/evidence_signing.py), the same way as
  the auditor's export. Unzip and check it offline with the public key alone:
  ``python3 tools/verify_evidence.py manifest.json --keys hawk-evidence-keys.json``.
- ``pack.json``: the pack definition as it was used (framework, version, sources, requirements and their mapping).
- ``status.json``: each requirement's status now, with its controls' results and what was recorded about it.
- ``controls.json``: every control the pack uses, with its status and reason.
- ``audit-entries.jsonl``: the tenant's audit entries of the window whose actions the pack's requirements name (each
  with its sequence number and MAC, to check against the chain), reasons with secrets taken out.
- ``settings.json``: the settings in force: sign-in and password rule, retention, data location, HTTPS, encryption
  at rest, detection (category toggles and thresholds, never word lists or fingerprints), the AI approval policy.
- ``records.json``: licence acceptances, AI approvals granted or ended in the window, the AI system inventory (name,
  tier, status), attestations, self-recovery, machine checks and detector coverage; for packs that cite them, the
  requests from data subjects (kind, dates, status, trail), never whom they are about.
- ``README.txt``: what each file is and how to check it.

Never in it: passwords or their hashes, two-step secrets, keys, connector credentials, prompt or response text,
dictionary words or fingerprinted values. Each export is recorded in the audit log.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import zipfile
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.services import compliance_packs, evidence_signing
from app.services.compliance_packs import controls as registry

MANIFEST_FORMAT = "hawk-evidence-manifest/v1"
BUNDLE_FORMAT = "hawk-compliance-pack-evidence/v1"
MAX_WINDOW_DAYS = 366
MAX_ENTRIES = 20_000
#: A fixed time for every file in the zip, so the same content makes the same bytes.
ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def _iso(value: Any) -> str | None:
    if not isinstance(value, dt.datetime):
        return None
    moment = value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, default=str) + "\n").encode("utf-8")


def _prefixes(pack_def: dict[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    for req in pack_def["requirements"]:
        for source in req["evidence"]:
            for prefix in compliance_packs.EVIDENCE_SOURCES[source]:
                if prefix not in out:
                    out.append(prefix)
    return tuple(out)


def audit_entries(db: Session, *, tenant_id: str, prefixes: tuple[str, ...], since: dt.datetime, until: dt.datetime) -> tuple[list[dict[str, Any]], bool]:
    from app.db.models.audit import AuditLog
    from app.services.privacy_sanitizer import redact_sensitive_text

    if not prefixes:
        return [], False
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id, AuditLog.created_at >= since, AuditLog.created_at <= until, or_(*(AuditLog.action.startswith(p) for p in prefixes)))
        .order_by(AuditLog.created_at, AuditLog.seq)
        .limit(MAX_ENTRIES + 1)
    ).all()
    out = []
    for row in rows[:MAX_ENTRIES]:
        payload = row.payload if isinstance(row.payload, dict) else {}
        out.append({
            "at": _iso(row.created_at),
            "seq": row.seq,
            "mac": row.mac,
            "action": row.action,
            "actorType": row.actor_type,
            "actorUserId": row.actor_user_id,
            "target": f"{row.resource_type} {row.resource_id}".strip(),
            "outcome": str(payload.get("outcome") or ""),
            "reason": redact_sensitive_text(payload.get("reason") or "", max_len=500),
        })
    return out, len(rows) > MAX_ENTRIES


def settings_snapshot(db: Session, tenant_id: str) -> dict[str, Any]:
    from app.services import account_security, ai_system_approval_service, compliance_service, password_policy
    from app.services.detection import settings_service

    sign_in = account_security.policy(db)
    detection = settings_service.view(db, tenant_id)
    config = detection["config"]
    dlp = config.get("dlp") or {}
    return {
        "signIn": {
            "passwordRule": password_policy.rule(db).view(),
            "passwordRuleInWords": password_policy.describe(password_policy.rule(db)),
            "twoStepRequired": bool(sign_in.two_step_required),
            "idleMinutes": account_security.idle_minutes(db),
            "noticeShown": bool((sign_in.banner_text or "").strip()),
            "passwordReset": sign_in.password_reset,
            "lockAfterWrong": account_security.MAX_FAILED,
            "lockMinutes": account_security.LOCK_SECONDS // 60,
            "companySso": bool(settings.company_sso_enabled),
            "ssoPasswordsForAdminsOnly": bool(sign_in.sso_password_admins_only),
        },
        "compliance": compliance_service.settings_view(db),
        "encryption": compliance_service.encryption_status(),
        "https": compliance_service._https_view(),
        "detection": {
            "revision": detection["revision"],
            "updatedAt": detection["updated_at"],
            "updatedBy": detection["updated_by"],
            "categories": dlp.get("categories") or {},
            "sensitiveCategories": dlp.get("sensitive_categories") or [],
            "documentMinScore": dlp.get("document_min_score"),
            "namedEntities": dlp.get("ner_enabled"),
            "customDictionaries": [{"id": d.get("id"), "name": d.get("name"), "category": d.get("category"), "terms": len(d.get("terms") or [])} for d in dlp.get("custom_dictionaries") or [] if isinstance(d, dict)],
            "fingerprintSets": [{k: s.get(k) for k in ("id", "name", "category", "count", "enabled", "created_at")} for s in detection["fingerprint_sets"]],
            "promptInjection": config.get("prompt_injection") or {},
        },
        "aiApprovalPolicy": ai_system_approval_service.load_config(db, tenant_id),
    }


def records(db: Session, tenant_id: str, *, since: dt.datetime, until: dt.datetime, pack_id: str) -> dict[str, Any]:
    from app.db.models.access import TermsAcceptance
    from app.db.models.ai_system import AISystem
    from app.db.models.ai_system_approval import AISystemApprovalGrant
    from app.services import self_recovery, terms_service
    from app.services.guardians.threat_detectors import coverage_matrix

    # This tenant's acceptances, and the organisation's acceptance made for the whole installation (ACCEPT_TERMS, or
    # before 0103 recorded the tenant). A person's own acceptance with no tenant (every one made before 0103) can be
    # anyone's on this installation: their name, email and address stay out of another tenant's bundle.
    acceptances = db.scalars(
        select(TermsAcceptance)
        .where(or_(TermsAcceptance.tenant_id == tenant_id, and_(TermsAcceptance.tenant_id.is_(None), TermsAcceptance.scope == "organisation")))
        .order_by(TermsAcceptance.accepted_at)
    ).all()
    grants = db.scalars(
        select(AISystemApprovalGrant)
        .where(AISystemApprovalGrant.tenant_id == tenant_id, or_(AISystemApprovalGrant.created_at.between(since, until), AISystemApprovalGrant.ended_at.between(since, until), AISystemApprovalGrant.state == "ACTIVE"))
    ).all()
    systems = db.scalars(select(AISystem).where(AISystem.tenant_id == tenant_id).order_by(AISystem.name)).all()
    recorded = compliance_packs.attestations(db, tenant_id, pack_id)
    now = dt.datetime.now(dt.timezone.utc)
    try:
        recovery = self_recovery.SelfRecovery().view(installation=False, tenant_id=tenant_id)
        operations = {"selfRecovery": {k: recovery.get(k) for k in ("lastRunAt", "everyMinutes", "needsOem", "needsOemReferences", "issues")}}
    except Exception as exc:  # noqa: BLE001
        operations = {"selfRecovery": {"error": type(exc).__name__}}
    try:
        from app.services.self_check import SelfCheck

        operations["machineChecks"] = SelfCheck().host_checks()
    except Exception as exc:  # noqa: BLE001
        operations["machineChecks"] = {"error": type(exc).__name__}
    out = {
        "termsAcceptances": [{k: v for k, v in terms_service.acceptance_view(a).items() if k != "userAgent"} for a in acceptances],
        "aiApprovals": [
            {
                "id": g.id,
                "aiSystemId": g.ai_system_id,
                "scope": g.scope,
                "state": g.state,
                "riskTier": g.risk_tier,
                "origin": g.origin,
                "requestedBy": g.requested_by,
                "approvers": list(g.approver_user_ids or []),
                "createdAt": _iso(getattr(g, "created_at", None)),
                "expiresAt": _iso(g.expires_at),
                "endedAt": _iso(g.ended_at),
                "endReason": g.end_reason,
            }
            for g in grants
        ],
        "aiInventory": [{"id": s.id, "name": s.name, "riskTier": s.risk_tier, "status": s.status} for s in systems],
        "attestations": [{"requirement": rid, **compliance_packs.attestation_view(row, now)} for (_, rid), row in sorted(recorded.items())],
        "operations": operations,
        "detectorCoverage": [{k: r.get(k) for k in ("detector_id", "title", "threat_type", "severity", "decision", "owasp_llm", "owasp_agentic", "mitre_atlas")} for r in coverage_matrix()],
    }
    # Requests from data subjects, for the packs whose requirements cite them (DPDP, UAE PDPL, ISO 27001): each request's
    # kind, dates, status and trail, never whom it is about.
    pack_def = compliance_packs.pack(pack_id)
    if any("records:data_subject_requests" in req["evidence"] for req in pack_def["requirements"]):
        from app.services import data_subject_requests

        out["dataSubjectRequests"] = data_subject_requests.evidence_records(db, tenant_id, since=since, until=until, now=now)
    return out


README = """Hawk AI compliance pack evidence
================================

Pack: {name} ({framework_version}), pack version {version}
Window: {since} to {until}
Made: {made} by {who}

{disclaimer}

Files
-----
manifest.json        Every other file by name and SHA-256, signed with this installation's evidence key.
pack.json            The pack as it was used: framework, sources, requirements and the Hawk AI controls mapped to each.
status.json          Each requirement's status when this bundle was made, its controls' results and any record.
controls.json        Each control the pack uses: status, reason, and where it is set.
audit-entries.jsonl  The audit entries of the window that the requirements name, with sequence numbers and MACs.
settings.json        The settings in force (sign-in, retention, encryption, detection, AI approval policy).
records.json         Licence acceptances, AI approvals, the AI system inventory, records made on the Compliance page,
                     self-recovery, machine checks, detector coverage and, for privacy laws, requests from data
                     subjects (kind, dates, status and trail; never whom they are about).

Checking it
-----------
1. Save the public keys from <your Hawk AI address>/.well-known/hawk-evidence-keys.json.
2. Unzip this bundle into a folder and run, from a copy of Hawk AI's tools folder:
       python3 tools/verify_evidence.py manifest.json --keys hawk-evidence-keys.json
   It checks the signature and that no file changed since. Each audit entry's sequence number and MAC can be
   compared with Settings -> Audit log -> Verify.

Never in this bundle: passwords, secrets, keys, connector credentials, prompt or response text, word lists or
fingerprinted values.
"""


def build(db: Session, *, tenant_id: str, pack_id: str, since: dt.datetime, until: dt.datetime, generated_by: str) -> tuple[bytes, dict[str, Any]]:
    """The zip and its signed manifest. Raises PackError for a bad window, EvidenceSigningError when it cannot be signed."""

    if since >= until:
        raise compliance_packs.PackError("The window must start before it ends.")
    if until - since > dt.timedelta(days=MAX_WINDOW_DAYS):
        raise compliance_packs.PackError(f"A pack's evidence covers at most {MAX_WINDOW_DAYS} days.")
    pack_def = compliance_packs.pack(pack_id)
    now = dt.datetime.now(dt.timezone.utc)
    evaluator = registry.Evaluator(registry.Context(db, tenant_id, now=now))
    status = compliance_packs.evaluate_pack(db, tenant_id, pack_id, evaluator=evaluator, now=now)
    entries, truncated = audit_entries(db, tenant_id=tenant_id, prefixes=_prefixes(pack_def), since=since, until=until)
    window = {"from": _iso(since), "to": _iso(until)}
    files: dict[str, bytes] = {
        "pack.json": _dump(pack_def),
        "status.json": _dump({"window": window, **{k: status[k] for k in ("id", "version", "framework", "summary", "requirements", "disclaimer", "evaluatedAt")}}),
        "controls.json": _dump({"controls": [evaluator.results[ref] for ref in sorted(evaluator.results)]}),
        "audit-entries.jsonl": "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in entries).encode("utf-8"),
        "settings.json": _dump(settings_snapshot(db, tenant_id)),
        "records.json": _dump(records(db, tenant_id, since=since, until=until, pack_id=pack_id)),
    }
    files["README.txt"] = README.format(
        name=pack_def["framework"]["name"],
        framework_version=pack_def["framework"]["version"],
        version=pack_def["version"],
        since=window["from"],
        until=window["to"],
        made=_iso(now),
        who=generated_by,
        disclaimer=compliance_packs.DISCLAIMER,
    ).encode("utf-8")
    manifest = {
        "format": MANIFEST_FORMAT,
        "kind": BUNDLE_FORMAT,
        "tenant_id": tenant_id,
        "pack": {"id": pack_def["id"], "version": pack_def["version"], "framework": pack_def["framework"]["name"], "frameworkVersion": pack_def["framework"]["version"]},
        "window": window,
        "period_start": window["from"],
        "period_end": window["to"],
        "generated_at": _iso(now),
        "generated_by": generated_by,
        "summary": {k: v for k, v in status["summary"].items() if k != "byApplicability"},
        "auditEntries": len(entries),
        "auditEntriesTruncated": truncated,
        "files": {name: {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in sorted(files.items())},
        "disclaimer": compliance_packs.DISCLAIMER,
    }
    signed = evidence_signing.service().sign_document(manifest, artifact=f"compliance_pack.{pack_def['id']}.manifest")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in [("manifest.json", (json.dumps(signed, indent=2, ensure_ascii=False) + "\n").encode("utf-8")), *sorted(files.items())]:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return buffer.getvalue(), signed


__all__ = ["BUNDLE_FORMAT", "MANIFEST_FORMAT", "MAX_WINDOW_DAYS", "audit_entries", "build", "records", "settings_snapshot"]
