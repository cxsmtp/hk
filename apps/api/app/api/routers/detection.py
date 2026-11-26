"""DLP and prompt-injection detection: the tenant's settings (category toggles, custom dictionaries, injection
thresholds), exact-data-match fingerprint sets, what the detectors cover in this installation, and a test scan.

Everything runs on this server: nothing is sent to an outside AI service. Fingerprinted values are stored only as
salted digests and no response carries a scanned or fingerprinted value.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.detection import dlp_engine, injection_classifier, settings_service
from app.services.detection.categories import DOCUMENT_CATEGORIES, dictionary_terms
from app.services.detection.injection_engine import ENGINE_VERSION, assess, reason_code_catalogue
from app.services.detection.injection_rules import CATEGORIES as INJECTION_CATEGORIES
from app.services.detection.injection_rules import RULES, RULESET_VERSION
from app.services.detection.profile import ENTITY_TYPES, load_profile
from app.services.detection.structured import STRUCTURED_ENTITY_TYPES
from app.services.sensitive_data_detection_service import ner_status

router = APIRouter(prefix="/detection", tags=["detection"])

MAX_SCAN_CHARS = 32_000


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, "detail": message})


def _who(ctx: TenantContext) -> str:
    return (ctx.user.email if ctx.user else "") or ""


def coverage() -> dict[str, Any]:
    model = injection_classifier.model()
    return {
        "offline": True,
        "versions": {**dlp_engine.versions(), "injection_rules": RULESET_VERSION, "injection_engine": ENGINE_VERSION, "classifier": model.version},
        "dlp": {
            "validated_entity_types": list(STRUCTURED_ENTITY_TYPES),
            "toggleable_entity_types": list(ENTITY_TYPES),
            "document_categories": {category: dictionary_terms(category) for category in DOCUMENT_CATEGORIES},
            "named_entities": ner_status(),
            "obfuscation_handling": ["nfkc", "zero_width", "homoglyph", "leetspeak", "spaced_out", "base64", "base64url", "hex", "percent", "unicode_escape"],
        },
        "prompt_injection": {
            "rule_count": len(RULES),
            "categories": list(INJECTION_CATEGORIES),
            "languages": sorted({rule.language for rule in RULES}),
            "classifier": {"algorithm": injection_classifier.ALGORITHM, "training_samples": model.samples, "training_positives": model.positives},
            "reason_codes": reason_code_catalogue(),
        },
    }


@router.get("/settings")
def get_detection_settings(ctx: TenantContext = Depends(require_permission("policies.view")), db: Session = Depends(get_db)):
    return settings_service.view(db, ctx.tenant.id)


@router.put("/settings")
def put_detection_settings(
    body: dict[str, Any] | None = Body(default=None),
    ctx: TenantContext = Depends(require_permission("policies.manage")),
    db: Session = Depends(get_db),
):
    before = settings_service.view(db, ctx.tenant.id)["config"]
    try:
        after = settings_service.save_config(db, ctx.tenant.id, body or {}, by=_who(ctx))
    except settings_service.DetectionSettingsError as error:
        db.rollback()
        return _error(error.status_code, error.message)
    disabled = sorted(k for k, on in after["config"]["dlp"]["categories"].items() if not on)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="settings.detection",
        resource_type="settings",
        resource_id="detection",
        payload={
            "outcome": "changed",
            "reason": f"Detection settings: {len(disabled)} categories off, "
            f"{len(after['config']['dlp']['custom_dictionaries'])} custom dictionaries, "
            f"injection thresholds {after['config']['prompt_injection']['thresholds']}.",
            "disabled_categories": disabled,
            "dictionaries": [d["name"] for d in after["config"]["dlp"]["custom_dictionaries"]],
            "thresholds": after["config"]["prompt_injection"]["thresholds"],
            "before_thresholds": before["prompt_injection"]["thresholds"],
            "revision": after["revision"],
        },
    )
    db.commit()
    return after


@router.post("/fingerprints", status_code=201)
def add_fingerprints(
    body: dict[str, Any] | None = Body(default=None),
    ctx: TenantContext = Depends(require_permission("policies.manage")),
    db: Session = Depends(get_db),
):
    try:
        created = settings_service.add_fingerprint_set(db, ctx.tenant.id, body or {}, by=_who(ctx))
    except settings_service.DetectionSettingsError as error:
        db.rollback()
        return _error(error.status_code, error.message)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="settings.detection.fingerprints_added",
        resource_type="settings",
        resource_id=f"detection/fingerprints/{created['id']}",
        payload={"outcome": "changed", "reason": f"Exact data match set '{created['name']}': {created['count']} values (salted digests only).", **created},
    )
    db.commit()
    return created


@router.delete("/fingerprints/{set_id}")
def delete_fingerprints(set_id: str, ctx: TenantContext = Depends(require_permission("policies.manage")), db: Session = Depends(get_db)):
    if not settings_service.delete_fingerprint_set(db, ctx.tenant.id, set_id, by=_who(ctx)):
        db.rollback()
        return _error(404, "No such fingerprint set.")
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="settings.detection.fingerprints_deleted",
        resource_type="settings",
        resource_id=f"detection/fingerprints/{set_id}",
        payload={"outcome": "changed", "reason": "Exact data match set deleted.", "id": set_id},
    )
    db.commit()
    return {"deleted": set_id}


@router.get("/coverage")
def get_detection_coverage(ctx: TenantContext = Depends(require_permission("policies.view"))):
    del ctx
    return coverage()


@router.post("/scan")
def scan_text(
    body: dict[str, Any] | None = Body(default=None),
    ctx: TenantContext = Depends(require_permission("policies.operate")),
    db: Session = Depends(get_db),
):
    """Try the tenant's detectors on a text. Returns types, scores and reason codes only, never the matched values."""
    body = body or {}
    text = body.get("text")
    if not isinstance(text, str) or not text.strip():
        return _error(400, "text is required")
    if len(text) > MAX_SCAN_CHARS:
        return _error(413, f"text is limited to {MAX_SCAN_CHARS} characters")
    scope = body.get("scope") if body.get("scope") in ("direct", "indirect") else "direct"
    profile = load_profile(db, ctx.tenant.id)
    result = dlp_engine.scan(text, profile=profile)
    findings = [
        {
            "entity_type": f.entity_type,
            "confidence": f.confidence,
            "detector": f.detector,
            "subtype": f.subtype,
            "context_word": f.context_hit,
            "encoded": f.encoded,
            "reasons": list(f.reasons),
            "start": None if f.encoded else result.normalized.original_span(f.start, f.end)[0],
            "end": None if f.encoded else result.normalized.original_span(f.start, f.end)[1],
        }
        for f in result.reportable()
        if profile.enabled(f.entity_type)
    ]
    verdict = assess(text, scope=scope, profile=profile)
    return {
        "dlp": {
            "findings": findings,
            "document_categories": [r.to_dict() for r in result.detected_categories(profile).values()],
            "exact_data_matches": result.edm_matches,
            "obfuscation": result.obfuscation,
            "named_entities": ner_status(),
        },
        "prompt_injection": verdict.to_dict(),
        "profile_revision": profile.revision,
    }
