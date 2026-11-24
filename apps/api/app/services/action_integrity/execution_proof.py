"""Lossless V2 authorised-versus-executed material comparison."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping
from uuid import uuid4

from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .materiality import material_fields, material_fields_hash
from .signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


EXECUTION_RECEIPT_DOMAIN = "hawk:execution-receipt:v2"
EXECUTION_COMPARISON_DOMAIN = "hawk:authorization-execution-comparison:v2"

EXECUTION_STATES = frozenset({
    "PROPOSED", "AWAITING_POLICY", "AWAITING_APPROVAL", "AUTHORISED", "BLOCKED",
    "PERMIT_ISSUED", "EXECUTION_STARTED", "QUEUED", "IN_PROGRESS", "EXECUTED",
    "PARTIALLY_EXECUTED", "FAILED", "CANCELLED", "EXPIRED", "DRIFTED",
    "UNVERIFIED", "UNKNOWN",
})
EVIDENCE_QUALITIES = frozenset({
    "PROVIDER_REPORTED", "HAWK_NATIVE_OBSERVED", "HAWK_ENDPOINT_OBSERVED",
    "HAWK_RUNTIME_OBSERVED", "TARGET_SERVICE_CONFIRMED", "EXTERNAL_SYSTEM_CONFIRMED",
    "INDEPENDENTLY_VERIFIED", "CORRELATED", "INFERRED", "UNKNOWN",
})
COMPARISON_RESULTS = frozenset({
    "MATCHED", "SEMANTICALLY_MATCHED", "PARTIAL", "DRIFTED", "UNVERIFIED", "FAILED", "BLOCKED", "PENDING",
})


def normalize_execution_state(value: object, *, verified_non_invocation: bool = False, execution_evidence: bool = False) -> str:
    """Map legacy/provider labels without promoting an unproven execution."""
    state = str(value or "").upper()
    aliases = {
        "STARTED": "EXECUTION_STARTED", "PARTIAL": "PARTIALLY_EXECUTED",
        "TIMED_OUT": "UNKNOWN", "NOT_EXECUTED": "BLOCKED", "DENIED": "BLOCKED",
        "SUCCESS": "EXECUTED", "SUCCEEDED": "EXECUTED",
    }
    state = aliases.get(state, state)
    if state in {"BLOCKED"} and not verified_non_invocation:
        return "UNKNOWN"
    if state == "EXECUTED" and not execution_evidence:
        return "UNVERIFIED"
    if state not in EXECUTION_STATES:
        return "UNKNOWN"
    return state


def normalize_evidence_quality(value: object) -> str:
    aliases = {"OS_AUTHORIZED": "HAWK_ENDPOINT_OBSERVED", "OS_DENIED": "HAWK_ENDPOINT_OBSERVED", "NATIVE_SEMANTIC": "HAWK_NATIVE_OBSERVED"}
    normalized = aliases.get(str(value or "").upper(), str(value or "").upper())
    if normalized not in EVIDENCE_QUALITIES:
        raise ValueError("unknown execution evidence quality")
    return normalized


def compare_authorized_to_executed(authorized: Mapping[str, Any], executed: Mapping[str, Any]) -> dict[str, Any]:
    """Compare the complete material-field union without exposing raw values.

    An unresolved field is an uncertainty, never an exact match.  The hashes
    deliberately let the finding/evidence layer prove the difference without
    persisting secrets or provider payloads a second time.
    """
    expected, actual = material_fields(authorized), material_fields(executed)
    differences = [path for path in sorted(set(expected) | set(actual)) if expected.get(path) != actual.get(path)]
    unresolved = sorted({*(str(item) for item in authorized.get("unresolved_material") or []), *(str(item) for item in executed.get("unresolved_material") or [])})
    if unresolved:
        result = "UNVERIFIED"
    else:
        result = "MATCHED" if not differences else "DRIFTED"
    return {
        "result": result,
        "drift_fields": differences,
        "unresolved_fields": unresolved,
        "authorized_fields": expected,
        "executed_fields": actual,
        "difference_hashes": [
            {"path": path, "authorized_hash": domain_hash("hawk:authorized-material-field:v1", {"path": path, "value": expected.get(path)}), "executed_hash": domain_hash("hawk:executed-material-field:v1", {"path": path, "value": actual.get(path)})}
            for path in differences
        ],
    }


def issue_execution_receipt_v2(
    provider: SigningKeyProvider,
    *,
    tenant_id: str,
    attempt_id: str,
    permit_id: str | None,
    authorized: Mapping[str, Any],
    executed: Mapping[str, Any],
    terminal_state: str,
    evidence_quality: str,
    issued_at: datetime,
    effect_closure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if authorized.get("tenant_id") != tenant_id or executed.get("tenant_id") != tenant_id:
        raise ValueError("execution receipt tenant mismatch")
    terminal_state = normalize_execution_state(
        terminal_state,
        verified_non_invocation=evidence_quality in {"HAWK_RUNTIME_OBSERVED", "HAWK_ENDPOINT_OBSERVED"},
        execution_evidence=evidence_quality not in {"PROVIDER_REPORTED", "UNKNOWN"},
    )
    evidence_quality = normalize_evidence_quality(evidence_quality)
    key_id = active_key_id(provider, purpose="execution_receipt_signing", tenant_id=tenant_id)
    closure = dict(effect_closure or {})
    if closure:
        required = {"reservation_id", "state", "provider_effect_ref", "evidence_refs", "recovery_sequence"}
        if set(closure) != required or not isinstance(closure["evidence_refs"], list):
            raise ValueError("execution effect closure fields are invalid")
    return sign_object(
        provider,
        purpose="execution_receipt_signing",
        domain=EXECUTION_RECEIPT_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value={
            "schema_version": "2.0", "receipt_id": str(uuid4()), "tenant_id": tenant_id, "attempt_id": attempt_id, "permit_id": permit_id,
            "canonical_action_hash": canonical_action_hash_v2(authorized), "actual_material_fields_hash": material_fields_hash(executed),
            "terminal_state": terminal_state, "evidence_quality": evidence_quality,
            "effect_closure": closure or None, "issued_at": issued_at.isoformat(),
        },
    )


def signed_execution_comparison(
    provider: SigningKeyProvider,
    *,
    tenant_id: str,
    attempt_id: str,
    authorized: Mapping[str, Any],
    executed: Mapping[str, Any],
    issued_at: datetime,
) -> dict[str, Any]:
    comparison = compare_authorized_to_executed(authorized, executed)
    key_id = active_key_id(provider, purpose="execution_comparison_signing", tenant_id=tenant_id)
    return sign_object(provider, purpose="execution_comparison_signing", domain=EXECUTION_COMPARISON_DOMAIN, tenant_id=tenant_id, key_id=key_id, value={"schema_version": "2.0", "comparison_id": str(uuid4()), "tenant_id": tenant_id, "attempt_id": attempt_id, "canonical_action_hash": canonical_action_hash_v2(authorized), "material_fields_hash": material_fields_hash(authorized), "result": comparison["result"], "drift_fields": comparison["drift_fields"], "unresolved_fields": comparison["unresolved_fields"], "difference_hashes": comparison["difference_hashes"], "issued_at": issued_at.isoformat()})


def verify_execution_receipt_v2(provider: SigningKeyProvider, receipt: Mapping[str, Any]) -> bool:
    tenant_id = receipt.get("tenant_id")
    return isinstance(tenant_id, str) and verify_signed_object(provider, purpose="execution_receipt_signing", domain=EXECUTION_RECEIPT_DOMAIN, tenant_id=tenant_id, value=dict(receipt), current_authority=False)


def verify_execution_comparison(provider: SigningKeyProvider, comparison: Mapping[str, Any]) -> bool:
    tenant_id = comparison.get("tenant_id")
    if not isinstance(tenant_id, str) or comparison.get("result") not in COMPARISON_RESULTS:
        return False
    if comparison.get("result") in {"MATCHED", "SEMANTICALLY_MATCHED"} and (comparison.get("drift_fields") or comparison.get("unresolved_fields")):
        return False
    return verify_signed_object(provider, purpose="execution_comparison_signing", domain=EXECUTION_COMPARISON_DOMAIN, tenant_id=tenant_id, value=dict(comparison), current_authority=False)
