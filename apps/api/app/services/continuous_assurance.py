"""Phase 6 P0 continuous validation, drift and regression authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import DecisionReceiptV2Extension, ExecutionReceiptV2Extension
from app.db.models.continuous_assurance import (
    ASSURANCE_STATES,
    SAFETY_CLASSES,
    VALIDATION_OUTCOMES,
    AssuranceBaseline,
    ControlAssertion,
    ControlAssertionDependency,
    DriftSignal,
    ValidationEvidenceBundle,
    ValidationRemediation,
    ValidationRun,
    ValidationSafetyEnvelope,
    ValidationScenario,
)
from app.db.models.native_control import ControlCapabilityProfileRecord
from app.services.control_coverage.service import phase5_action_assurance_evidence


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
_ALLOWED_DEPENDENCIES = frozenset(
    {
        "provider_control_capability",
        "model_runtime",
        "agent_configuration",
        "tool_mcp_fingerprint",
        "identity_permission",
        "subject_resource_mapping",
        "account_boundary",
        "policy",
        "domain_profile",
        "route_control_point",
        "execution_integrity",
        "target_mapping",
    }
)
_ACTION_TEMPLATE_KEYS = frozenset(
    {"fixture_ref", "action_class", "tool_ref", "target_ref", "side_effect"}
)
_SAFETY_ENVELOPE_KEYS = frozenset(
    {
        "allowed_action_classes",
        "allowed_targets",
        "allowed_control_points",
        "allowed_side_effect_categories",
        "cleanup_required",
    }
)
_EXECUTABLE_KEYS = frozenset(
    {
        "shell",
        "command",
        "commands",
        "python",
        "javascript",
        "script",
        "subprocess",
        "dynamic_import",
        "filesystem",
        "credential",
        "credentials",
        "target_url",
        "executable",
        "payload",
        "database_command",
    }
)
_PROHIBITED_ACTION_CLASSES = frozenset(
    {
        "real_financial_transfer",
        "real_medical_order",
        "real_citizen_decision",
        "real_industrial_control_command",
        "real_credential_creation",
        "real_external_disclosure",
        "production_deletion",
        "arbitrary_shell_execution",
        "malware",
        "credential_theft",
        "unauthorized_third_party_targeting",
    }
)
_PASS_OUTCOMES = frozenset(
    {"PASS_CONTROLLED", "PASS_DETECTED", "PASS_PREVENTED", "PASS_EXECUTION_MATCHED"}
)
_EXPECTED_POLICY_RESULTS = frozenset({"ALLOW", "BLOCK", "REQUIRE_APPROVAL"})
_EXPECTED_ENFORCEMENT_RESULTS = frozenset({"EXECUTED", "PREVENTED", "BLOCKED", "DETECTED"})
_EXPECTED_RECEIPT_RESULTS = frozenset({"MATCHED", "NOT_EXECUTED", "OBSERVED"})
_REGRESSION_OUTCOMES = frozenset(
    {
        "FAIL_MISSED",
        "FAIL_EXECUTED",
        "FAIL_WRONG_DECISION",
        "FAIL_WRONG_CONTROL_POINT",
        "FAIL_EVIDENCE_MISSING",
        "FAIL_SAFETY_BOUNDARY",
    }
)
_EVIDENCE_RANK = {
    "UNKNOWN": 0,
    "INFERRED": 1,
    "PROVIDER_REPORTED": 1,
    "CORRELATED": 2,
    "HAWK_NATIVE_OBSERVED": 3,
    "HAWK_ENDPOINT_OBSERVED": 3,
    "HAWK_RUNTIME_OBSERVED": 3,
    "TARGET_SERVICE_CONFIRMED": 4,
    "EXTERNAL_SYSTEM_CONFIRMED": 4,
    "INDEPENDENTLY_VERIFIED": 5,
}


@dataclass(frozen=True, slots=True)
class Phase5EvidenceReference:
    action_id: str
    decision_receipt_id: str | None
    execution_receipt_id: str | None
    comparison_id: str | None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("assurance timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def _reference(value: object, *, field: str, maximum: int = 255) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{field} is invalid")
    if not _REFERENCE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError("dependency digest must be lowercase SHA-256")
    return value


def _canonical_hash(domain: str, value: Mapping[str, object]) -> str:
    material = json.dumps(
        {"domain": domain, "value": dict(value)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _bounded_string_list(value: object, *, field: str, maximum_items: int = 32) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError(f"{field} is invalid")
    return [_reference(item, field=field) for item in value]


def _contains_executable_material(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _EXECUTABLE_KEYS or _contains_executable_material(item):
                return True
    elif isinstance(value, list):
        return any(_contains_executable_material(item) for item in value)
    return False


def _stored_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class ContinuousAssuranceService:
    """Own the P0 assurance state machine; never execute arbitrary scenario code."""

    def create_assertion(
        self,
        db: Session,
        *,
        tenant_id: str,
        assertion_key: str,
        assertion_type: str,
        asset_ref: str | None,
        action_class: str | None,
        required_capability: str,
        expected_outcome: str,
        required_evidence_level: str,
        dependencies: Mapping[str, str],
        control_profile_id: str | None = None,
    ) -> ControlAssertion:
        tenant_id = _reference(tenant_id, field="tenant id", maximum=36)
        assertion_key = _reference(assertion_key, field="assertion key", maximum=128)
        if expected_outcome not in VALIDATION_OUTCOMES:
            raise ValueError("expected assertion outcome is unsupported")
        if required_evidence_level not in _EVIDENCE_RANK:
            raise ValueError("required evidence level is unsupported")
        if not isinstance(dependencies, Mapping) or not 1 <= len(dependencies) <= 64:
            raise ValueError("assertion dependencies are invalid")
        existing = db.scalar(
            select(ControlAssertion).where(
                ControlAssertion.tenant_id == tenant_id,
                ControlAssertion.assertion_key == assertion_key,
            )
        )
        if existing is not None:
            return existing
        row = ControlAssertion(
            tenant_id=tenant_id,
            assertion_key=assertion_key,
            assertion_type=_reference(assertion_type, field="assertion type", maximum=64),
            asset_ref=_reference(asset_ref, field="asset reference") if asset_ref else None,
            action_class=_reference(action_class, field="action class", maximum=128) if action_class else None,
            required_capability=_reference(required_capability, field="required capability", maximum=128),
            expected_outcome=expected_outcome,
            required_evidence_level=required_evidence_level,
            assurance_state="UNKNOWN",
            assurance_version=0,
            control_profile_id=control_profile_id,
        )
        db.add(row)
        db.flush()
        for combined, current_digest in sorted(dependencies.items()):
            if not isinstance(combined, str) or ":" not in combined:
                raise ValueError("dependency key must include category and identity")
            category, dependency_key = combined.split(":", 1)
            if category not in _ALLOWED_DEPENDENCIES:
                raise ValueError("dependency category is unsupported")
            row.dependencies.append(
                ControlAssertionDependency(
                    tenant_id=tenant_id,
                    assertion_id=row.id,
                    dependency_category=category,
                    dependency_key=_reference(dependency_key, field="dependency key"),
                    current_digest=_digest(current_digest),
                )
            )
        db.flush()
        self._project_capability_assurance(db, assertion=row)
        return row

    def create_scenario(
        self,
        db: Session,
        *,
        tenant_id: str,
        assertion_id: str,
        scenario_key: str,
        action_template: Mapping[str, object],
        expected_policy_result: str,
        expected_enforcement_result: str,
        expected_receipt_result: str,
        safety_class: str,
        safety_envelope: Mapping[str, object],
        mutations: list[dict[str, object]],
        expected_validation_outcome: str,
        freshness_seconds: int = 86400,
    ) -> ValidationScenario:
        tenant_id = _reference(tenant_id, field="tenant id", maximum=36)
        assertion = db.scalar(
            select(ControlAssertion).where(
                ControlAssertion.tenant_id == tenant_id,
                ControlAssertion.id == assertion_id,
            )
        )
        if assertion is None:
            raise PermissionError("validation assertion tenant binding is invalid")
        if safety_class not in SAFETY_CLASSES:
            raise ValueError("validation safety class is unsupported")
        if expected_validation_outcome not in VALIDATION_OUTCOMES:
            raise ValueError("validation outcome is unsupported")
        if type(freshness_seconds) is not int or not 1 <= freshness_seconds <= 31_536_000:
            raise ValueError("validation freshness is invalid")
        if _contains_executable_material(action_template) or _contains_executable_material(mutations):
            raise ValueError("executable scenario material is prohibited")
        if not isinstance(action_template, Mapping) or set(action_template) - _ACTION_TEMPLATE_KEYS:
            raise ValueError("validation action template is not declarative")
        if set(safety_envelope) - _SAFETY_ENVELOPE_KEYS:
            raise ValueError("validation safety envelope contains unsupported material")
        if (
            not isinstance(mutations, list)
            or len(mutations) > 16
            or any(not isinstance(item, Mapping) for item in mutations)
        ):
            raise ValueError("validation mutations are invalid")
        policy_result = _reference(
            expected_policy_result, field="expected policy result", maximum=32
        ).upper()
        enforcement_result = _reference(
            expected_enforcement_result, field="expected enforcement result", maximum=32
        ).upper()
        receipt_result = _reference(
            expected_receipt_result, field="expected receipt result", maximum=32
        ).upper()
        if policy_result not in _EXPECTED_POLICY_RESULTS:
            raise ValueError("expected policy result is unsupported")
        if enforcement_result not in _EXPECTED_ENFORCEMENT_RESULTS:
            raise ValueError("expected enforcement result is unsupported")
        if receipt_result not in _EXPECTED_RECEIPT_RESULTS:
            raise ValueError("expected receipt result is unsupported")
        if expected_validation_outcome == "PASS_EXECUTION_MATCHED" and (
            enforcement_result != "EXECUTED" or receipt_result != "MATCHED"
        ):
            raise ValueError("execution-matched scenario contract is inconsistent")
        if expected_validation_outcome == "PASS_PREVENTED" and (
            policy_result != "BLOCK"
            or enforcement_result not in {"PREVENTED", "BLOCKED"}
            or receipt_result != "NOT_EXECUTED"
        ):
            raise ValueError("prevention scenario contract is inconsistent")
        fixture_ref = _reference(action_template.get("fixture_ref"), field="fixture reference")
        target_ref = _reference(action_template.get("target_ref"), field="target reference")
        tenant_fixture_prefix = f"fixture:{tenant_id}:"
        if not fixture_ref.startswith(tenant_fixture_prefix) or not target_ref.startswith(tenant_fixture_prefix):
            raise PermissionError("validation target is outside the tenant fixture boundary")
        envelope = ValidationSafetyEnvelope(
            tenant_id=tenant_id,
            allowed_action_classes=_bounded_string_list(
                safety_envelope.get("allowed_action_classes"), field="allowed action classes"
            ),
            allowed_targets=_bounded_string_list(
                safety_envelope.get("allowed_targets"), field="allowed targets"
            ),
            allowed_control_points=_bounded_string_list(
                safety_envelope.get("allowed_control_points"), field="allowed control points"
            ),
            allowed_side_effect_categories=_bounded_string_list(
                safety_envelope.get("allowed_side_effect_categories"), field="allowed side effects"
            ),
            cleanup_required=safety_envelope.get("cleanup_required") is True,
            production_canary_authorized=False,
            approved_at=datetime.now(timezone.utc),
        )
        db.add(envelope)
        db.flush()
        row = ValidationScenario(
            tenant_id=tenant_id,
            assertion_id=assertion.id,
            safety_envelope_id=envelope.id,
            scenario_key=_reference(scenario_key, field="scenario key", maximum=128),
            action_template=dict(action_template),
            expected_policy_result=policy_result,
            expected_enforcement_result=enforcement_result,
            expected_receipt_result=receipt_result,
            safety_class=safety_class,
            mutations=list(mutations),
            expected_validation_outcome=expected_validation_outcome,
            freshness_seconds=freshness_seconds,
            approved=True,
            active=True,
        )
        db.add(row)
        db.flush()
        return row

    def start_validation(
        self,
        db: Session,
        *,
        tenant_id: str,
        scenario_id: str,
        trigger: str,
        triggered_by_ref: str,
        started_at: datetime,
        drift_signal_id: str | None = None,
        remediation_id: str | None = None,
    ) -> ValidationRun:
        at = _utc(started_at)
        scenario = db.scalar(
            select(ValidationScenario)
            .where(ValidationScenario.tenant_id == tenant_id, ValidationScenario.id == scenario_id)
            .with_for_update()
        )
        if scenario is None:
            raise PermissionError("validation scenario tenant binding is invalid")
        assertion = db.scalar(
            select(ControlAssertion)
            .where(ControlAssertion.tenant_id == tenant_id, ControlAssertion.id == scenario.assertion_id)
            .with_for_update()
        )
        safety = db.scalar(
            select(ValidationSafetyEnvelope).where(
                ValidationSafetyEnvelope.tenant_id == tenant_id,
                ValidationSafetyEnvelope.id == scenario.safety_envelope_id,
            )
        )
        if assertion is None or safety is None or not scenario.approved or not scenario.active:
            raise PermissionError("validation scenario is not approved and current")
        self._enforce_safety(scenario=scenario, envelope=safety)
        row = ValidationRun(
            tenant_id=tenant_id,
            assertion_id=assertion.id,
            scenario_id=scenario.id,
            trigger=_reference(trigger, field="validation trigger", maximum=32),
            triggered_by_ref=_reference(triggered_by_ref, field="validation principal"),
            drift_signal_id=drift_signal_id,
            remediation_id=remediation_id,
            status="STARTED",
            prior_assurance_state=assertion.assurance_state,
            started_at=at,
        )
        db.add(row)
        db.flush()
        return row

    def complete_validation(
        self,
        db: Session,
        *,
        tenant_id: str,
        run_id: str,
        phase5_evidence: Phase5EvidenceReference,
        completed_at: datetime,
    ) -> ValidationRun:
        at = _utc(completed_at)
        run = db.scalar(
            select(ValidationRun)
            .where(ValidationRun.tenant_id == tenant_id, ValidationRun.id == run_id)
            .with_for_update()
        )
        if run is None:
            raise PermissionError("validation run tenant binding is invalid")
        if run.status != "STARTED" or run.completed_at is not None:
            raise ValueError("validation run is already terminal")
        assertion = db.scalar(
            select(ControlAssertion)
            .where(ControlAssertion.tenant_id == tenant_id, ControlAssertion.id == run.assertion_id)
            .with_for_update()
        )
        scenario = db.scalar(
            select(ValidationScenario).where(
                ValidationScenario.tenant_id == tenant_id,
                ValidationScenario.id == run.scenario_id,
            )
        )
        if assertion is None or scenario is None:
            raise PermissionError("validation authority is incomplete")
        outcome, reasons, bundle = self._evaluate_phase5(
            db,
            tenant_id=tenant_id,
            run=run,
            assertion=assertion,
            scenario=scenario,
            evidence=phase5_evidence,
            evaluated_at=at,
        )
        db.add(bundle)
        db.flush()
        run.status = "COMPLETED"
        run.outcome = outcome
        run.reason_codes = reasons
        run.completed_at = at
        run.evidence_bundle_id = bundle.id
        if outcome in _PASS_OUTCOMES:
            dependency_state = {
                f"{item.dependency_category}:{item.dependency_key}": item.current_digest
                for item in assertion.dependencies
            }
            baseline_version = assertion.assurance_version + 1
            baseline = AssuranceBaseline(
                tenant_id=tenant_id,
                assertion_id=assertion.id,
                baseline_version=baseline_version,
                dependency_state=dependency_state,
                dependency_hash=_canonical_hash("hawk:assurance-baseline:v1", dependency_state),
                validation_run_id=run.id,
                valid_from=at,
                valid_until=at + timedelta(seconds=scenario.freshness_seconds),
            )
            db.add(baseline)
            db.flush()
            bundle.baseline_id = baseline.id
            assertion.current_baseline_id = baseline.id
            assertion.last_validation_run_id = run.id
            assertion.last_validated_at = at
            assertion.fresh_until = baseline.valid_until
            assertion.assurance_version = baseline_version
            assertion.assurance_state = "CURRENT"
            if run.remediation_id:
                remediation = db.scalar(
                    select(ValidationRemediation)
                    .where(
                        ValidationRemediation.tenant_id == tenant_id,
                        ValidationRemediation.id == run.remediation_id,
                    )
                    .with_for_update()
                )
                if remediation is None or remediation.assertion_id != assertion.id:
                    raise PermissionError("validation remediation binding is invalid")
                remediation.state = "RESOLVED"
                remediation.revalidation_required = False
                remediation.resolved_validation_run_id = run.id
                regression_run = db.scalar(
                    select(ValidationRun).where(
                        ValidationRun.tenant_id == tenant_id,
                        ValidationRun.id == remediation.regression_run_id,
                    )
                )
                if regression_run is not None and regression_run.drift_signal_id:
                    drift = db.scalar(
                        select(DriftSignal).where(
                            DriftSignal.tenant_id == tenant_id,
                            DriftSignal.id == regression_run.drift_signal_id,
                        )
                    )
                    if drift is not None:
                        drift.status = "REVALIDATED"
        elif outcome in _REGRESSION_OUTCOMES:
            if assertion.current_baseline_id is not None or assertion.last_validation_run_id is not None:
                assertion.assurance_state = "REGRESSED"
            else:
                assertion.assurance_state = "UNKNOWN"
        self._project_capability_assurance(db, assertion=assertion)
        db.flush()
        return run

    def record_drift(
        self,
        db: Session,
        *,
        tenant_id: str,
        category: str,
        dependency_key: str,
        previous_digest: str,
        current_digest: str,
        source_ref: str,
        observed_at: datetime,
    ) -> DriftSignal:
        at = _utc(observed_at)
        if category not in _ALLOWED_DEPENDENCIES:
            raise ValueError("drift category is unsupported")
        dependency_key = _reference(dependency_key, field="dependency key")
        previous_digest, current_digest = _digest(previous_digest), _digest(current_digest)
        if previous_digest == current_digest:
            raise ValueError("drift must change material dependency state")
        source_ref = _reference(source_ref, field="drift source")
        signal_hash = _canonical_hash(
            "hawk:assurance-drift-signal:v1",
            {
                "tenant_id": tenant_id,
                "category": category,
                "dependency_key": dependency_key,
                "previous_digest": previous_digest,
                "current_digest": current_digest,
                "source_ref": source_ref,
                "observed_at": at.isoformat(),
            },
        )
        existing = db.scalar(
            select(DriftSignal).where(
                DriftSignal.tenant_id == tenant_id,
                DriftSignal.signal_hash == signal_hash,
            )
        )
        if existing is not None:
            return existing
        bindings = tuple(
            db.scalars(
                select(ControlAssertionDependency)
                .where(
                    ControlAssertionDependency.tenant_id == tenant_id,
                    ControlAssertionDependency.dependency_category == category,
                    ControlAssertionDependency.dependency_key == dependency_key,
                )
                .with_for_update()
            ).all()
        )
        affected: list[str] = []
        for binding in bindings:
            if binding.current_digest != previous_digest:
                continue
            binding.current_digest = current_digest
            assertion = db.scalar(
                select(ControlAssertion)
                .where(
                    ControlAssertion.tenant_id == tenant_id,
                    ControlAssertion.id == binding.assertion_id,
                )
                .with_for_update()
            )
            if assertion is None:
                continue
            affected.append(assertion.id)
            if assertion.assurance_state == "CURRENT":
                assertion.assurance_state = "STALE"
                assertion.fresh_until = at
                self._project_capability_assurance(db, assertion=assertion)
        row = DriftSignal(
            tenant_id=tenant_id,
            signal_hash=signal_hash,
            category=category,
            dependency_key=dependency_key,
            previous_digest=previous_digest,
            current_digest=current_digest,
            source_ref=source_ref,
            affected_assertion_ids=sorted(affected),
            status="OPEN",
            observed_at=at,
        )
        db.add(row)
        db.flush()
        return row

    def expire_due_assertions(
        self,
        db: Session,
        *,
        tenant_id: str,
        evaluated_at: datetime,
    ) -> tuple[str, ...]:
        """Expire only tenant-bound CURRENT assertions whose evidence aged out."""

        at = _utc(evaluated_at)
        rows = tuple(
            db.scalars(
                select(ControlAssertion)
                .where(
                    ControlAssertion.tenant_id == tenant_id,
                    ControlAssertion.assurance_state == "CURRENT",
                    ControlAssertion.fresh_until.is_not(None),
                    ControlAssertion.fresh_until <= at,
                )
                .with_for_update()
            ).all()
        )
        for row in rows:
            row.assurance_state = "STALE"
            self._project_capability_assurance(db, assertion=row)
        db.flush()
        return tuple(sorted(row.id for row in rows))

    def start_targeted_revalidation(
        self,
        db: Session,
        *,
        tenant_id: str,
        assertion_id: str,
        started_at: datetime,
        drift_signal_id: str | None = None,
        remediation_id: str | None = None,
    ) -> ValidationRun:
        assertion = db.scalar(
            select(ControlAssertion).where(
                ControlAssertion.tenant_id == tenant_id,
                ControlAssertion.id == assertion_id,
            )
        )
        if assertion is None:
            raise PermissionError("targeted assertion tenant binding is invalid")
        scenario = db.scalar(
            select(ValidationScenario)
            .where(
                ValidationScenario.tenant_id == tenant_id,
                ValidationScenario.assertion_id == assertion_id,
                ValidationScenario.active.is_(True),
                ValidationScenario.approved.is_(True),
            )
            .order_by(ValidationScenario.updated_at.desc(), ValidationScenario.id.desc())
        )
        if scenario is None:
            raise PermissionError("targeted revalidation has no approved scenario")
        if remediation_id:
            remediation = db.scalar(
                select(ValidationRemediation).where(
                    ValidationRemediation.tenant_id == tenant_id,
                    ValidationRemediation.id == remediation_id,
                )
            )
            if (
                remediation is None
                or remediation.assertion_id != assertion_id
                or remediation.state != "READY_FOR_REVALIDATION"
            ):
                raise PermissionError("remediation is not ready for targeted revalidation")
        return self.start_validation(
            db,
            tenant_id=tenant_id,
            scenario_id=scenario.id,
            trigger="remediation" if remediation_id else "drift",
            triggered_by_ref="system:continuous-assurance",
            started_at=started_at,
            drift_signal_id=drift_signal_id,
            remediation_id=remediation_id,
        )

    def create_remediation(
        self,
        db: Session,
        *,
        tenant_id: str,
        assertion_id: str,
        regression_run_id: str,
        reason: str,
        created_by_ref: str,
        created_at: datetime,
    ) -> ValidationRemediation:
        _utc(created_at)
        assertion = db.scalar(
            select(ControlAssertion).where(
                ControlAssertion.tenant_id == tenant_id,
                ControlAssertion.id == assertion_id,
            )
        )
        run = db.scalar(
            select(ValidationRun).where(
                ValidationRun.tenant_id == tenant_id,
                ValidationRun.id == regression_run_id,
            )
        )
        if (
            assertion is None
            or assertion.assurance_state != "REGRESSED"
            or run is None
            or run.assertion_id != assertion_id
            or run.outcome not in _REGRESSION_OUTCOMES
        ):
            raise PermissionError("remediation requires a tenant-bound regression")
        principal = _reference(created_by_ref, field="remediation principal")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
            raise ValueError("remediation reason is invalid")
        row = ValidationRemediation(
            tenant_id=tenant_id,
            assertion_id=assertion_id,
            regression_run_id=regression_run_id,
            reason=reason.strip(),
            state="OPEN",
            revalidation_required=True,
            created_by_ref=principal,
            updated_by_ref=principal,
        )
        db.add(row)
        db.flush()
        return row

    def mark_remediation_ready(
        self,
        db: Session,
        *,
        tenant_id: str,
        remediation_id: str,
        updated_by_ref: str,
        updated_at: datetime,
    ) -> ValidationRemediation:
        _utc(updated_at)
        row = db.scalar(
            select(ValidationRemediation)
            .where(
                ValidationRemediation.tenant_id == tenant_id,
                ValidationRemediation.id == remediation_id,
            )
            .with_for_update()
        )
        if row is None or row.state != "OPEN":
            raise PermissionError("remediation cannot enter revalidation")
        row.state = "READY_FOR_REVALIDATION"
        row.updated_by_ref = _reference(updated_by_ref, field="remediation principal")
        return row

    @staticmethod
    def _enforce_safety(
        *, scenario: ValidationScenario, envelope: ValidationSafetyEnvelope
    ) -> None:
        if scenario.safety_class == "S5_PROHIBITED":
            raise PermissionError("S5 validation scenarios are never executable")
        if scenario.safety_class == "S4_PRODUCTION_CANARY" and not envelope.production_canary_authorized:
            raise PermissionError("S4 validation requires explicit production canary safeguards")
        action = dict(scenario.action_template or {})
        action_class = str(action.get("action_class") or "")
        target = str(action.get("target_ref") or "")
        side_effect = str(action.get("side_effect") or "")
        if action_class in _PROHIBITED_ACTION_CLASSES or side_effect in _PROHIBITED_ACTION_CLASSES:
            raise PermissionError("prohibited validation action cannot execute")
        if (
            action_class not in set(envelope.allowed_action_classes or [])
            or target not in set(envelope.allowed_targets or [])
            or side_effect not in set(envelope.allowed_side_effect_categories or [])
            or not envelope.allowed_control_points
        ):
            raise PermissionError("validation safety boundary is not satisfied")
        if scenario.safety_class in {"S2_REVERSIBLE_TEST_STATE", "S3_ISOLATED_SIDE_EFFECT"} and not envelope.cleanup_required:
            raise PermissionError("stateful validation requires declared cleanup")

    def _evaluate_phase5(
        self,
        db: Session,
        *,
        tenant_id: str,
        run: ValidationRun,
        assertion: ControlAssertion,
        scenario: ValidationScenario,
        evidence: Phase5EvidenceReference,
        evaluated_at: datetime,
    ) -> tuple[str, list[str], ValidationEvidenceBundle]:
        proof = phase5_action_assurance_evidence(
            db,
            tenant_id=tenant_id,
            action_id=evidence.action_id,
            now=evaluated_at,
        )
        decision = (
            db.scalar(
                select(DecisionReceiptV2Extension).where(
                    DecisionReceiptV2Extension.tenant_id == tenant_id,
                    DecisionReceiptV2Extension.receipt_id == evidence.decision_receipt_id,
                    DecisionReceiptV2Extension.action_id == evidence.action_id,
                )
            )
            if evidence.decision_receipt_id
            else None
        )
        execution = (
            db.scalar(
                select(ExecutionReceiptV2Extension).where(
                    ExecutionReceiptV2Extension.tenant_id == tenant_id,
                    ExecutionReceiptV2Extension.receipt_id == evidence.execution_receipt_id,
                )
            )
            if evidence.execution_receipt_id
            else None
        )
        refs = set(proof.evidence_refs)
        exact_decision = (
            decision is not None
            and proof.decision_verified
            and f"decision_receipt:{decision.receipt_id}" in refs
        )
        exact_execution = (
            execution is not None
            and proof.execution_visible
            and f"execution_receipt:{execution.receipt_id}" in refs
        )
        exact_comparison = bool(
            evidence.comparison_id
            and proof.execution_matched
            and f"evidence:phase5:execution_comparison:{evidence.comparison_id}" in refs
        )
        evidence_quality = str(execution.evidence_quality if execution is not None else "UNKNOWN")
        expected_policy = scenario.expected_policy_result.upper()
        expected_enforcement = scenario.expected_enforcement_result.upper()
        authoritative_decision = str(decision.authoritative_decision if decision is not None else "")
        reasons: list[str] = []
        canonical = self._decision_canonical_action(decision)
        action_semantics = canonical.get("action_semantics")
        semantics = action_semantics if isinstance(action_semantics, Mapping) else {}
        template = dict(scenario.action_template or {})
        target_refs = semantics.get("target_refs")
        resource_scopes = canonical.get("resource_scopes")
        safety = db.scalar(
            select(ValidationSafetyEnvelope).where(
                ValidationSafetyEnvelope.tenant_id == tenant_id,
                ValidationSafetyEnvelope.id == scenario.safety_envelope_id,
            )
        )
        allowed_control_points = set(safety.allowed_control_points or []) if safety is not None else set()
        material_matches = (
            canonical.get("tenant_id") == tenant_id
            and semantics.get("tool_or_service_ref") == template.get("tool_ref")
            and isinstance(target_refs, list)
            and template.get("target_ref") in target_refs
            and isinstance(resource_scopes, list)
            and template.get("target_ref") in resource_scopes
            and semantics.get("side_effect") == template.get("side_effect")
            and canonical.get("provider_runtime_context")
            in allowed_control_points
        )
        if not exact_decision:
            outcome = "FAIL_EVIDENCE_MISSING"
            reasons.append("phase5_decision_evidence_missing_or_invalid")
        elif not material_matches:
            outcome = "FAIL_WRONG_CONTROL_POINT"
            reasons.append("phase5_evidence_not_bound_to_validation_scenario")
        elif expected_policy and authoritative_decision != expected_policy:
            outcome = "FAIL_WRONG_DECISION"
            reasons.append("phase5_policy_decision_mismatch")
        elif expected_enforcement in {"PREVENTED", "BLOCKED"}:
            # A decision record or detection signal is not independent proof
            # that the protected callback did not execute.
            outcome = "FAIL_WRONG_CONTROL_POINT"
            reasons.append("prevention_not_proven_by_execution_boundary")
        elif expected_enforcement == "DETECTED":
            outcome = "PASS_DETECTED"
        elif not exact_execution or not evidence.comparison_id:
            outcome = "FAIL_EVIDENCE_MISSING"
            reasons.append("phase5_execution_evidence_missing")
        elif proof.execution_failed:
            outcome = "FAIL_EXECUTED"
            reasons.append("phase5_authorized_execution_drifted")
        elif not exact_comparison:
            outcome = "FAIL_EVIDENCE_MISSING"
            reasons.append("phase5_execution_comparison_missing_or_invalid")
        elif _EVIDENCE_RANK.get(evidence_quality, 0) < _EVIDENCE_RANK[assertion.required_evidence_level]:
            outcome = "FAIL_EVIDENCE_MISSING"
            reasons.append("phase5_evidence_quality_below_assertion")
        else:
            outcome = "PASS_EXECUTION_MATCHED"
        if outcome in _PASS_OUTCOMES and outcome != scenario.expected_validation_outcome:
            outcome = "FAIL_WRONG_DECISION"
            reasons.append("validation_outcome_did_not_match_scenario_contract")
        bundle = ValidationEvidenceBundle(
            tenant_id=tenant_id,
            validation_run_id=run.id,
            assertion_id=assertion.id,
            action_id=evidence.action_id,
            decision_receipt_id=evidence.decision_receipt_id if exact_decision else None,
            execution_receipt_id=evidence.execution_receipt_id if exact_execution else None,
            comparison_id=evidence.comparison_id if exact_comparison else None,
            selected_control_point_id=decision.control_selection_id if exact_decision else None,
            policy_version=self._decision_policy_version(decision),
            policy_epoch=decision.policy_epoch if exact_decision else None,
            evidence_quality=evidence_quality,
            target_confirmed=proof.outcome_verified and material_matches,
            evidence_refs=sorted(refs),
        )
        return outcome, reasons, bundle

    @staticmethod
    def _decision_policy_version(decision: DecisionReceiptV2Extension | None) -> str | None:
        if decision is None or not isinstance(decision.signed_envelope, Mapping):
            return None
        canonical = decision.signed_envelope.get("canonical_action")
        if not isinstance(canonical, Mapping):
            return None
        value = canonical.get("policy_version_id")
        return str(value) if isinstance(value, str) and value else None

    @staticmethod
    def _decision_canonical_action(
        decision: DecisionReceiptV2Extension | None,
    ) -> Mapping[str, object]:
        if decision is None or not isinstance(decision.signed_envelope, Mapping):
            return {}
        value = decision.signed_envelope.get("canonical_action")
        return value if isinstance(value, Mapping) else {}

    def _project_capability_assurance(self, db: Session, *, assertion: ControlAssertion) -> None:
        if not assertion.control_profile_id:
            return
        profile = db.get(ControlCapabilityProfileRecord, assertion.control_profile_id)
        if profile is None:
            raise PermissionError("control assertion profile reference is invalid")
        rows = tuple(
            db.scalars(
                select(ControlAssertion).where(
                    ControlAssertion.control_profile_id == profile.id,
                    ControlAssertion.required_capability == assertion.required_capability,
                )
            ).all()
        )
        rank = {"CURRENT": 0, "UNKNOWN": 1, "STALE": 2, "REGRESSED": 3}
        state = max((row.assurance_state for row in rows), key=lambda value: rank.get(value, 3), default="UNKNOWN")
        capabilities = dict(profile.capabilities or {})
        claim = dict(capabilities.get(assertion.required_capability) or {})
        if not claim:
            raise PermissionError("control assertion capability is absent from the profile")
        claim["assurance_state"] = state.lower()
        claim["assurance_assertion_ids"] = sorted(row.id for row in rows)
        capabilities[assertion.required_capability] = claim
        profile.capabilities = capabilities
