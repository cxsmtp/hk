#!/usr/bin/env python3
"""Prove signed software-hook repository controls using disposable local services.

The per-run software signing helper is a test fixture, never hardware or managed
endpoint enrollment evidence. No models, installed hooks, or shared databases run.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import cProfile
import functools
import math
import pstats
import threading
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT_SRC = ROOT / "apps/endpoint-agent/src"
SAFE_REASONS = frozenset({
    "repository_control_floor", "repository_operation_blocked",
    "repository_runtime_binding_required", "repository_runtime_target_unresolved",
    "repository_governance_not_current", "CONTROL_REQUIREMENT_UNSATISFIED",
    "deployment_acceptance_lifecycle_mismatch", "provider_event_id_reauthorization_required",
})

DIAGNOSTIC_EXCEPTION_CLASSES = frozenset({
    "ValidationError", "ValueError", "RuntimeError", "ModuleNotFoundError", "ImportError",
    "SyntaxError", "OperationalError", "ProgrammingError", "IntegrityError", "DataError",
    "InternalError", "DatabaseError", "PermissionError", "FileNotFoundError", "TimeoutExpired",
})
SQLSTATE_REASONS = {
    "42703": "migration_undefined_column", "42P01": "migration_missing_table",
    "42710": "migration_duplicate_object", "42P07": "migration_duplicate_table",
    "23503": "migration_foreign_key_violation", "23502": "migration_not_null_violation",
    "23514": "migration_check_constraint_violation", "23505": "migration_unique_violation",
    "22001": "migration_value_too_long", "42601": "migration_syntax_error",
    "42501": "migration_insufficient_privilege", "42883": "migration_undefined_function",
    "42704": "migration_undefined_object", "42P17": "migration_invalid_object_definition",
    "42P16": "migration_invalid_table_definition", "42804": "migration_datatype_mismatch",
    "0A000": "migration_unsupported_feature", "28P01": "migration_authentication_failed",
}


def acceptance_lab_flags() -> dict[str, str]:
    flags = {key: "true" for key in ("NATIVE_CONTROL_ADAPTER_FRAMEWORK", "NATIVE_CONTROL_REFERENCE_ADAPTERS", "NATIVE_CONTROL_ADAPTER_ENFORCEMENT", "CONTROL_CAPABILITY_MATRIX", "NATIVE_CONTROL_MONITOR", "NATIVE_CONTROL_ENFORCE", "NATIVE_CONTROL_ANTHROPIC", "AUTHORIZATION_KERNEL_V2_ENABLED", "AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED", "DISCOVERY_CONTEXT_PROVIDER")}
    return {**flags, "ENV": "production", "SELF_REGISTRATION_ENABLED": "false", "CANONICAL_ACTION_BINDING_KEY": secrets.token_urlsafe(48)}


def diagnostic_projection(stage: str, private_log: str, *, passed: bool) -> dict:
    """Discard all raw log data; retain only closed diagnostic facts."""
    require(stage in {"settings", "postgres_prepare", "migrations"}, "diagnostic_stage_invalid")
    facts = {}
    for line in private_log.splitlines():
        if line.startswith("HAWK_DIAGNOSTIC_FACTS="):
            try:
                value = json.loads(line.removeprefix("HAWK_DIAGNOSTIC_FACTS="))
                if isinstance(value, dict):
                    facts = value
            except ValueError:
                pass
    exception = facts.get("exception_class")
    sqlstate = facts.get("sqlstate")
    reasons = [] if passed else [f"{stage}_failed"]
    if exception in {"ModuleNotFoundError", "ImportError"}:
        reasons.append("dependency_missing")
    if stage == "settings":
        for marker, code in (
            ("SECRET_KEY must be", "settings_secret_key_invalid"),
            ("Production configuration preflight failed", "production_configuration_preflight_failed"),
            ("requires an explicit tenant/surface rollout", "kernel_rollout_missing"),
            ("AUTHORIZATION_KERNEL_V2_ENABLED=true", "kernel_v2_prerequisite_missing"),
            ("CANONICAL_ACTION_BINDING_KEY is required when authorization kernel v2 is enabled.", "canonical_action_binding_key_missing"),
            ("SELF_REGISTRATION_ENABLED requires a recognized dev, test, or demo ENV and cannot be combined with PILOT_MODE.", "self_registration_environment_invalid"),
        ):
            if marker in private_log:
                reasons.append(code)
    if stage == "migrations" and sqlstate in SQLSTATE_REASONS:
        reasons.append(SQLSTATE_REASONS[sqlstate])
    revisions = re.findall(r"Running upgrade [^\n]*? -> ([0-9]{4}_[a-z0-9_]{1,90})(?:,|\s|$)", private_log)
    return {
        "stage": stage, "status": "passed" if passed else "blocked",
        "exception_class": exception if exception in DIAGNOSTIC_EXCEPTION_CLASSES else None,
        "allowlisted_reason_codes": sorted(set(reasons)),
        "sqlstate": sqlstate if sqlstate in SQLSTATE_REASONS else None,
        "revision": revisions[-1] if stage == "migrations" and revisions else None,
    }


def _diagnostic_child_program(stage: str) -> str:
    target = "from app.core.config import settings" if stage == "settings" else f"import runpy; runpy.run_path({str(ROOT / 'infra/scripts/run_migrations.py')!r}, run_name='__main__')"
    return "import json, sys, traceback\ntry:\n    " + target + "\nexcept Exception as exc:\n    traceback.print_exc()\n    cause = exc\n    sqlstate = None\n    for _ in range(4):\n        sqlstate = getattr(cause, 'pgcode', None) or getattr(cause, 'sqlstate', None) or sqlstate\n        cause = getattr(cause, 'orig', None) or getattr(cause, '__cause__', None)\n        if cause is None:\n            break\n    print('HAWK_DIAGNOSTIC_FACTS=' + json.dumps({'exception_class': type(exc).__name__, 'sqlstate': sqlstate}), flush=True)\n    sys.exit(1)\n"


def run_migration_diagnostic(root: Path) -> dict:
    from isolated_hawk_lab import IsolatedHawkLab, PG_BIN, PYTHON
    lab = IsolatedHawkLab(root, extra_env=acceptance_lab_flags())
    stage = "settings"
    label = "diagnostic-settings"
    try:
        lab.prepare()
        try:
            lab._run([str(PYTHON), "-c", _diagnostic_child_program("settings")], label, timeout=45)
        except RuntimeError:
            return diagnostic_projection(stage, (root / "logs" / f"{label}.log").read_text(errors="replace"), passed=False)
        # Start only owned PostgreSQL. No Redis, worker, API or hook is invoked.
        stage = "postgres_prepare"
        label = "diagnostic-initdb"
        lab._run([str(PG_BIN / "initdb"), "-D", str(root / "postgres-data"), "--username=hawk_lab", "--auth-host=scram-sha-256", "--auth-local=scram-sha-256", "--pwfile", str(root / "postgres-password")], label, timeout=120)
        lab.postgres_start_attempted = True
        label = "diagnostic-postgres-start"
        lab._run([str(PG_BIN / "pg_ctl"), "-D", str(root / "postgres-data"), "-l", str(root / "logs" / "postgres.log"), "-o", f"-h 127.0.0.1 -p {lab.ports['postgres']} -k {root / 'postgres-socket'}", "-w", "start"], label, timeout=60)
        lab.postgres_started = True
        label = "diagnostic-createdb"
        lab._run([str(PG_BIN / "createdb"), "-h", "127.0.0.1", "-p", str(lab.ports["postgres"]), "-U", "hawk_lab", "hawk_lab"], label, timeout=30)
        stage = "migrations"
        label = "diagnostic-migrations"
        try:
            lab._run([str(PYTHON), "-c", _diagnostic_child_program("migrations")], label, timeout=180)
        except RuntimeError:
            return diagnostic_projection(stage, (root / "logs" / f"{label}.log").read_text(errors="replace"), passed=False)
        return diagnostic_projection(stage, (root / "logs" / f"{label}.log").read_text(errors="replace"), passed=True)
    except Exception as exc:
        log = (root / "logs" / f"{label}.log")
        projection = diagnostic_projection(stage, log.read_text(errors="replace") if log.exists() else "", passed=False)
        if type(exc).__name__ in DIAGNOSTIC_EXCEPTION_CLASSES:
            projection["exception_class"] = type(exc).__name__
        return projection
    finally:
        lab.stop()


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def callback_projection(payload: dict, *, lifecycle: str, signal: str) -> dict:
    """Project closed evidence fields and one correlation hash only."""
    event_hash = str(payload.get("provider_event_id_hash") or "")
    return {
        "decision": payload.get("decision") if payload.get("decision") in {"allow", "block"} else "unknown",
        "enforced": payload.get("enforced") is True,
        "exact_adapter": payload.get("adapter_dispatch") == "exact",
        "authenticated": signal == "authenticated_native_adapter",
        "lifecycle_before_tool": lifecycle == "before_tool",
        "provider_event_hash": event_hash if re.fullmatch(r"[0-9a-f]{64}", event_hash) else "unknown",
        "reason_codes": sorted(set(payload.get("reason_codes") or []) & SAFE_REASONS),
    }


def validate_report(report: dict) -> None:
    require(report.get("signer") == "software_test_only", "signer_scope_invalid")
    require(report.get("strict_health") is True and report.get("migration_0092") is True, "isolated_schema_not_ready")
    phases = report.get("phases") or []
    require(len(phases) == 3, "causal_phase_count_invalid")
    hashes = set()
    for phase, expected in zip(phases, ("allow", "block", "allow"), strict=True):
        require(phase.get("decision") == expected and phase.get("hook_decision") == ("deny" if expected == "block" else "allow"), "causal_decision_mismatch")
        require(all(phase.get(key) is True for key in ("enforced", "exact_adapter", "authenticated", "lifecycle_before_tool")), "causal_authority_missing")
        digest = phase.get("provider_event_hash", "")
        require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)), "causal_event_hash_invalid")
        hashes.add(digest)
    require(len(hashes) == 3, "causal_events_not_distinct")
    require({"repository_control_floor", "repository_operation_blocked"} <= set(phases[1].get("reason_codes") or []), "repository_floor_evidence_missing")
    require(report.get("scratch_unchanged") is True, "scratch_marker_changed")
    require(report.get("release_ready") is False, "release_readiness_overclaim")


def _recv(connection, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = connection.recv(size - len(output))
        if not chunk:
            raise RuntimeError("signer_transport_closed")
        output.extend(chunk)
    return bytes(output)


def serve_software_signer(path: Path) -> None:
    """One per-run key lives only in this private helper process."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    require(path.parent.is_dir() and path.parent.stat().st_mode & 0o077 == 0, "signer_directory_not_private")
    key = ec.generate_private_key(ec.SECP256R1())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(2)
        public_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        print(json.dumps({"public_key_pem": public_pem}), flush=True)
        try:
            while True:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    size = struct.unpack("!I", _recv(connection, 4))[0]
                    require(0 < size <= 1_048_576, "signer_request_size_invalid")
                    request = json.loads(_recv(connection, size))
                    valid = request.get("protocol") == "hawk-kms-helper/1.0" and request.get("key_reference") == "kms://isolated-software-test"
                    response = {"protocol": "hawk-kms-helper/1.0", "request_id": request.get("request_id"), "key_id": "kms://isolated-software-test", "algorithm": "ES256", "ok": valid}
                    if valid and request.get("verb") == "sign":
                        payload = base64.b64decode(request["payload_base64"], validate=True)
                        response["signature"] = base64.urlsafe_b64encode(key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode().rstrip("=")
                    else:
                        response["ok"] = False
                    encoded = json.dumps(response, separators=(",", ":")).encode()
                    connection.sendall(struct.pack("!I", len(encoded)) + encoded)
        finally:
            path.unlink(missing_ok=True)


def seed_current_repository(tenant_id: str, now: datetime, *, session_factory=None) -> tuple[str, str]:
    """Current repository/policy/discovery fixtures; all controls use public APIs."""
    from app.db.session import SessionLocal
    from app.db.models.github_repository_access import GitHubRepository, GitHubSourceOrganization
    from app.db.models.policy import PolicyPack, PolicyVersion
    from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
    from app.db.models.ai_asset import DiscoveryAIAsset
    from app.db.models.discovery_resolution import DiscoveryResolutionGraphNode, DiscoveryAssetHypothesis
    from app.db.models.evidence_resolution import DiscoveryAIEcosystem, DiscoveryEcosystemMembership, DiscoveryHypothesisEvaluation
    from app.db.models.discovery_verification import DiscoveryVerificationAssertion, DiscoveryVerificationPolicy, DiscoveryVerificationEpisode
    from app.db.models.capability_inference import DiscoveryCapabilityGenome, DiscoveryCapabilityInferenceRun
    from app.db.models.evidence import EvidenceNode
    from app.services.policy_pack_platform.service import _normalize_assignment_targets
    with (session_factory or SessionLocal)() as db:
        source = GitHubSourceOrganization(tenant_id=tenant_id, host="github.com", external_organization_id="floor-org", login="floor-org")
        db.add(source)
        db.flush()
        repository = GitHubRepository(
            tenant_id=tenant_id,
            source_organization_id=source.id,
            host="github.com",
            external_repository_id="floor-repo",
            full_name="floor-org/private-repo",
            evidence_state="CONFIRMED",
            visibility="PRIVATE",
            lifecycle_state="ACTIVE",
            first_seen_at=now,
            last_seen_at=now,
            last_verified_at=now,
        )
        db.add(repository)
        db.flush()
        pack = PolicyPack(id=str(uuid4()), tenant_id=tenant_id, name="Repository floor", description="test", status="active")
        version = PolicyVersion(id=str(uuid4()), tenant_id=tenant_id, pack_id=pack.id, version="1", scope={}, enforcement_defaults={}, guardian_contracts=[], contract_json={})
        definition = PolicyPackDefinition(id=str(uuid4()), publisher_ref="test-repository-floor", stable_pack_id="TEST-REPOSITORY-FLOOR", version="1", name="Repository floor", description="test", state="PUBLISHED")
        instance = PolicyPackInstance(id=str(uuid4()), tenant_id=tenant_id, definition_id=definition.id, source_pack_id="TEST-REPOSITORY-FLOOR", source_pack_version="1", runtime_policy_pack_id=pack.id, effective_policy_version_id=version.id, owner_ref="test-owner", state="ENFORCED")
        assignment = PolicyPackAssignment(
            id=str(uuid4()),
            tenant_id=tenant_id,
            instance_id=instance.id,
            assignment_key="repository-floor",
            targets=_normalize_assignment_targets({
                "application": ["github"],
                "deployment_surface": ["mcp_gateway"],
                "resource": [repository.id],
            }),
            active=True,
        )
        for row in (pack, version, definition, instance, assignment):
            db.add(row)
            db.flush()

        asset_id = str(uuid4())
        evidence_id = str(uuid4())
        digest = lambda: hashlib.sha256(uuid4().bytes).hexdigest()
        asset = DiscoveryAIAsset(
            asset_id=asset_id,
            tenant_id=tenant_id,
            asset_type="runtime",
            canonical_name="Claude Code",
            provider="anthropic",
            product="claude_code",
            framework="Read",
            version="2.1.183",
            deployment_family="endpoint",
            technical_surface="runtime",
            environment="production",
            approved_status="approved",
            lifecycle_status="active",
            shadow_ai_status="unknown",
            first_seen_at=now - timedelta(minutes=1),
            last_seen_at=now,
            resolution_confidence=0.95,
            evidence_bundle_id=evidence_id,
            projection_version=1,
        )
        graph_node_id = str(uuid4())
        genome_id = str(uuid4())
        ecosystem_id = str(uuid4())
        ecosystem_record_id = str(uuid4())
        run_id, hypothesis_id, evaluation_id, policy_id, episode_id = (str(uuid4()) for _ in range(5))
        parents = (
            EvidenceNode(id=evidence_id, tenant_id=tenant_id, node_type="evidence_bundle", signal_type="synthetic_repository_acceptance", label="Synthetic local test evidence bundle", payload={"synthetic": True, "purpose": "repository_acceptance_fixture"}),
            DiscoveryCapabilityInferenceRun(inference_run_id=run_id, tenant_id=tenant_id, evidence_node_id=evidence_id, subject_reference_hash="e" * 64, observation_ids_json=[], engine_version="1.0", catalog_version="1.0", ruleset_version="1.0", run_sequence=1, supersedes_run_id=None, recommended_asset_type="runtime", recommended_ecosystem="runtime", first_observed_at=now - timedelta(minutes=1), last_observed_at=now, validated_at=now, limitations_json=[], idempotency_key=uuid4().hex, input_digest=digest(), output_digest=digest()),
            DiscoveryAssetHypothesis(hypothesis_id=hypothesis_id, tenant_id=tenant_id, hypothesis_type="coding_assistant", state="hypothesized", label="Synthetic Claude Code hypothesis", candidate_key_hash=digest(), confidence=0.95, verification_state="verified", freshness="fresh", contradiction_state="none", evidence_node_id=evidence_id, promoted_asset_id=None, first_observed_at=now - timedelta(minutes=1), last_observed_at=now, version=1, idempotency_key=uuid4().hex, input_digest=digest()),
            DiscoveryHypothesisEvaluation(evaluation_id=evaluation_id, tenant_id=tenant_id, hypothesis_id=hypothesis_id, inference_run_id=run_id, predecessor_evaluation_id=None, evaluation_sequence=1, candidate_ecosystem_class="runtime", required_anchors_json=[], required_anchor_results_json=[], base_confidence=0.95, effective_confidence=0.95, evidence_quality=0.95, source_diversity=1, rule_id="synthetic-runtime", rule_version="1.0", confidence_methodology_id="synthetic-runtime", confidence_methodology_version="1.0", decay_policy_id="synthetic-runtime", decay_policy_version="1.0", threshold_considered=0.9, recommended_action="create_ecosystem", first_observed_at=now - timedelta(minutes=1), last_observed_at=now, validated_at=now, limitations_json=[], idempotency_key=uuid4().hex, input_digest=digest()),
            DiscoveryVerificationPolicy(policy_record_id=policy_id, tenant_id=tenant_id, policy_id="synthetic-runtime", version=1, predecessor_policy_record_id=None, ecosystem_classes_json=["runtime"], environments_json=["production"], minimum_evidence_quality=0.9, minimum_confidence=0.9, minimum_source_diversity=1, assertion_ttl_seconds=3600, rescan_interval_seconds=3600, effective_from=now - timedelta(minutes=1), effective_until=None, methodology_version="1.0", actor_id="synthetic-fixture", idempotency_key=uuid4().hex, input_digest=digest()),
        )
        for row in parents:
            db.add(row)
            db.flush()
        rows = (
            asset,
            DiscoveryResolutionGraphNode(
                graph_node_id=graph_node_id,
                tenant_id=tenant_id,
                node_class="ai_asset",
                subject_reference=f"discovery_asset:{asset_id}",
                idempotency_key=uuid4().hex,
                input_digest=digest(),
            ),
            DiscoveryCapabilityGenome(
                genome_id=genome_id,
                tenant_id=tenant_id,
                inference_run_id=run_id,
                subject_reference_hash="e" * 64,
                genome_version=1,
                supersedes_genome_id=None,
                genome_digest=digest(),
                capabilities_json=[],
                dependencies_json=[{"reference": "current"}],
                permissions_json=[],
                reachability_json=[],
                usage_json=[],
                models_json=[],
                providers_json=[],
                runtime_json=[],
                data_json=[],
                marketplace_json=[],
                identity_json=[],
                first_observed_at=now - timedelta(minutes=1),
                last_observed_at=now,
            ),
            DiscoveryAIEcosystem(
                ecosystem_record_id=ecosystem_record_id,
                tenant_id=tenant_id,
                ecosystem_id=ecosystem_id,
                resolution_version=1,
                supersedes_record_id=None,
                canonical_name="Claude Code test ecosystem",
                ecosystem_class="runtime",
                lifecycle_state="active",
                resolution_state="resolved",
                confidence=0.95,
                evidence_quality=0.95,
                capability_genome_id=genome_id,
                first_observed_at=now - timedelta(minutes=1),
                last_observed_at=now,
                last_validated_at=now,
                methodology_id="native-control-test",
                methodology_version="1.0",
                limitations_json=[],
                outstanding_contradictions=0,
                idempotency_key=uuid4().hex,
                input_digest=digest(),
            ),
            DiscoveryEcosystemMembership(
                membership_id=str(uuid4()),
                tenant_id=tenant_id,
                ecosystem_record_id=ecosystem_record_id,
                ecosystem_id=ecosystem_id,
                graph_node_id=graph_node_id,
                member_type="ai_asset",
                membership_state="active",
                membership_sequence=1,
                predecessor_membership_id=None,
                evidence_node_id=evidence_id,
                confidence=0.95,
                verification_state="verified",
                first_observed_at=now - timedelta(minutes=1),
                last_observed_at=now,
                limitations_json=[],
                input_digest=digest(),
            ),
            DiscoveryVerificationEpisode(episode_id=episode_id, tenant_id=tenant_id, ecosystem_id=ecosystem_id, ecosystem_record_id=ecosystem_record_id, hypothesis_evaluation_id=evaluation_id, policy_record_id=policy_id, environment="production", episode_sequence=1, predecessor_episode_id=None, trigger="synthetic_fixture", trigger_event_id=None, graph_input_digest=digest(), evidence_input_digest=digest(), policy_digest=digest(), started_at=now - timedelta(minutes=1), due_at=now, expires_at=now + timedelta(hours=1), limitations_json=[], idempotency_key=uuid4().hex, input_digest=digest()),
            DiscoveryVerificationAssertion(
                assertion_id=str(uuid4()),
                tenant_id=tenant_id,
                ecosystem_id=ecosystem_id,
                ecosystem_record_id=ecosystem_record_id,
                episode_id=episode_id,
                erg_evaluation_id=evaluation_id,
                policy_record_id=policy_id,
                predecessor_assertion_id=None,
                assertion_sequence=1,
                conclusion="verified",
                required_requirement_count=1,
                required_verified_count=1,
                optional_requirement_count=0,
                optional_verified_count=0,
                source_diversity=1,
                evidence_quality=0.95,
                verification_quality=0.95,
                issued_at=now - timedelta(minutes=1),
                valid_from=now - timedelta(minutes=1),
                valid_until=now + timedelta(hours=1),
                invalidated_at=None,
                methodology_version="1.0",
                limitations_json=[],
                contradictions_json=[],
                idempotency_key=uuid4().hex,
                input_digest=digest(),
            ),
        )
        for row in rows:
            db.add(row)
            db.flush()
        db.commit()
        repository_id = repository.id
        assignment_id = assignment.id

    return repository_id, assignment_id


SELECTOR_REASON_CODES = frozenset({
    'CONTROL_REQUIREMENT_UNSATISFIED',
    'action_field_destination_not_visible',
    'action_field_identity_not_visible',
    'action_field_parameters_not_visible',
    'action_field_result_not_visible',
    'action_field_target_not_visible',
    'active_bypass_detected',
    'adapter_version_route_mismatch',
    'adapter_version_unavailable',
    'adapter_version_unsupported',
    'asset_status_unknown',
    'blocked_action_type',
    'blocking_semantics_unavailable',
    'callback_authentication_failed',
    'callback_unauthenticated',
    'configuration_integrity_invalid',
    'degradation_mode_unacceptable',
    'deployment_acceptance_action_class_mismatch',
    'deployment_acceptance_adapter_version_mismatch',
    'deployment_acceptance_contract_hash_mismatch',
    'deployment_acceptance_control_method_mismatch',
    'deployment_acceptance_credential_inactive',
    'deployment_acceptance_credential_mismatch',
    'deployment_acceptance_deployment_identity_mismatch',
    'deployment_acceptance_deployment_mismatch',
    'deployment_acceptance_environment_mismatch',
    'deployment_acceptance_evidence_incomplete',
    'deployment_acceptance_lifecycle_mismatch',
    'deployment_acceptance_location_mismatch',
    'deployment_acceptance_model_mismatch',
    'deployment_acceptance_model_provider_mismatch',
    'deployment_acceptance_not_current',
    'deployment_acceptance_outcomes_incomplete',
    'deployment_acceptance_provider_product_mismatch',
    'deployment_acceptance_provider_version_mismatch',
    'deployment_acceptance_route_identity_mismatch',
    'deployment_acceptance_route_mismatch',
    'deployment_acceptance_runtime_mismatch',
    'deployment_acceptance_state_mismatch',
    'deployment_acceptance_synthetic',
    'enterprise_account_context_required',
    'enterprise_tenant_context_required',
    'evidence_flow_unavailable',
    'generic_observation_only',
    'insufficient_post_execution_verification',
    'latency_budget_exceeded',
    'latency_requirement_unsatisfied',
    'mandatory_enforcement_floor_unsatisfied',
    'minimum_assurance_unsatisfied',
    'missing_active_policies',
    'not_endpoint_enforcement_floor',
    'policy_binding_mode_unverified',
    'policy_stale',
    'policy_version_mismatch',
    'policy_version_unavailable',
    'profile_unverified',
    'provider_event_id_reauthorization_required',
    'provider_product_mismatch',
    'provider_version_route_mismatch',
    'provider_version_unavailable',
    'provider_version_unsupported',
    'repository_control_floor',
    'repository_operation_blocked',
    'repository_runtime_blocked',
    'repository_runtime_target_unresolved',
    'required_lifecycle_event_missing',
    'semantic_control_unsatisfied',
    'strongest_verified_eligible_control_point',
    'tenant_binding_invalid',
    'validation_stale',
})


def selector_projection(selection) -> dict:
    from app.services.native_control.contracts import CapabilityDimension, VerificationStatus, HealthState
    if selection is None:
        return {"status": "not_found"}
    capabilities = {dimension.value for dimension in CapabilityDimension}
    reasons = SELECTOR_REASON_CODES | {
        f"{prefix}{code}{suffix}" for code in capabilities
        for prefix, suffix in (("capability_", "_unverified"), ("capability_", "_unsatisfied"), ("insufficient_", ""))
    } | {f"profile_{state.value}" for state in VerificationStatus} | {f"health_{state.value}" for state in HealthState} | {
        f"action_field_{field}_not_visible" for field in (
            "action_type", "tool_name", "tool_class", "parameter_hash", "target_resource", "target_resource_hash",
            "destination", "destination_hash", "persistent_side_effect", "data_classifications",
        )
    }
    def filtered(value, allowed):
        return sorted({item for item in value if isinstance(item, str) and item in allowed}) if isinstance(value, (list, tuple)) else []
    candidates = selection.rejected_candidates if isinstance(selection.rejected_candidates, list) else []
    floors = selection.rejected_mandatory_floor_candidates
    if isinstance(floors, dict):
        candidates = candidates + [candidate for rows in floors.values() if isinstance(rows, list) for candidate in rows]
    rejected_reasons = {code for candidate in candidates if isinstance(candidate, dict)
                        for code in filtered(candidate.get("reason_codes"), reasons)}
    assurance = selection.assurance_level
    return {
        "status": "found",
        "required_capabilities": filtered(selection.required_capabilities, capabilities),
        "satisfied_capabilities": filtered(selection.satisfied_capabilities, capabilities),
        "unsatisfied_capabilities": filtered(selection.unsatisfied_capabilities, capabilities),
        "required_assurance": None,
        "assurance_level": assurance if type(assurance) is int and 0 <= assurance <= 5 else None,
        "rejected_candidate_count": min(len(candidates), 128),
        "selected_reason_codes": filtered([selection.selection_reason] + (selection.control_plan_reason_codes if isinstance(selection.control_plan_reason_codes, list) else []), reasons),
        "rejected_reason_codes": sorted(rejected_reasons),
    }


def latency_projection(samples, observed_p95, budget) -> dict:
    def bounded(value):
        return value if type(value) is int and 0 <= value <= 300000 else None
    measured = sorted(value for value in samples[:500] if bounded(value) is not None)
    p95, maximum = bounded(observed_p95), bounded(budget)
    return {
        "sample_count": len(measured), "latency_samples_ms": measured[:16],
        "minimum_ms": measured[0] if measured else None,
        "maximum_ms": measured[-1] if measured else None,
        "health_p95_ms": p95, "requirement_budget_ms": maximum,
        "p95_exceeds_budget": p95 > maximum if p95 is not None and maximum is not None else None,
    }


def _callback_latency_projection(db, tenant_id: str, integration_id: str) -> dict:
    from sqlalchemy import select
    from app.db.models.native_control import NativeControlHealthObservation
    from app.services.native_control.health import health_snapshot
    from app.core.control_engine.authorization import AuthorizationRequest
    from app.services.native_control.requirements import derive_control_requirements
    now = datetime.now(timezone.utc)
    credential_id, credential_epoch = "isolated-repository-workload", 1
    samples = list(db.scalars(select(NativeControlHealthObservation.latency_ms).where(
        NativeControlHealthObservation.tenant_id == tenant_id,
        NativeControlHealthObservation.integration_instance_id == integration_id,
        NativeControlHealthObservation.credential_id == credential_id,
        NativeControlHealthObservation.credential_epoch == credential_epoch,
        NativeControlHealthObservation.observed_at >= now - timedelta(minutes=5),
        NativeControlHealthObservation.observed_at <= now,
        NativeControlHealthObservation.expires_at >= now,
        NativeControlHealthObservation.source == "signed_native_callback",
        NativeControlHealthObservation.callback_authenticated.is_(True),
        NativeControlHealthObservation.evidence_flowing.is_(True),
    ).order_by(NativeControlHealthObservation.observed_at.desc()).limit(500)))
    snapshot = health_snapshot(db, tenant_id=tenant_id, integration_id=integration_id,
                               credential_id=credential_id, credential_epoch=credential_epoch, now=now)
    requirement = derive_control_requirements(AuthorizationRequest(
        tenant_id=tenant_id, environment="production", collector_id="isolated-repository-hook",
        action_id="isolated-latency-diagnostic", chain_id="isolated-latency-diagnostic",
        surface="runtime_control", policy_snapshot_id="policy-repository-floor",
        action={"action_type": "FILE_READ"}, target={"destination": "local"},
        side_effect_context={"persistent_side_effect": False}, policy_profile={},
    ))
    return latency_projection(samples, snapshot.observed_latency_ms, requirement.maximum_latency_ms)


def _evidence_for_hook(tenant_id: str, integration_id: str, before_ids: set[str]) -> dict:
    from sqlalchemy import select
    from app.db.session import SessionLocal
    from app.db.models.evidence import EvidenceNode
    from app.db.models.native_control import NativeControlSelection
    with SessionLocal() as db:
        rows = list(db.scalars(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.node_type == "native_control_callback")))
        rows = [row for row in rows if row.id not in before_ids and row.payload.get("integration_id") == integration_id]
        require(len(rows) == 1, "exact_hook_evidence_count_invalid")
        row = rows[0]
        selection_id = row.payload.get("native_control_selection_id")
        selection = db.scalar(select(NativeControlSelection).where(NativeControlSelection.tenant_id == tenant_id, NativeControlSelection.selection_id == selection_id)) if selection_id else None
        lifecycle = (selection.provider_runtime_context or {}).get("lifecycle_stage") if selection else "unknown"
        projection = callback_projection(row.payload, lifecycle=lifecycle, signal=row.signal_type)
        projection["selector"] = selector_projection(selection)
        projection["latency"] = _callback_latency_projection(db, tenant_id, integration_id)
        return projection


def run_hook(lab, config: Path, scratch: Path, tenant_id: str, integration_id: str, tool_id: str) -> dict:
    from sqlalchemy import select
    from app.db.session import SessionLocal
    from app.db.models.evidence import EvidenceNode
    with SessionLocal() as db:
        before_ids = set(db.scalars(select(EvidenceNode.id).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.node_type == "native_control_callback")))
    environment = {**lab.env, "PYTHONPATH": str(ENDPOINT_SRC)}
    raw = {"hook_event_name": "PreToolUse", "session_id": "isolated-repository-session", "tool_use_id": tool_id, "cwd": str(scratch), "tool_name": "Read", "tool_input": {"file_path": str(scratch / "README.md")}}
    process = subprocess.run([str(lab.env.get("REPOSITORY_HOOK_PYTHON") or sys.executable), "-m", "hawk_endpoint_agent.native_control.hook", "--hawk-managed-hook", "--provider", "claude_code", "--event", "before_tool", "--config", str(config)], input=json.dumps(raw).encode(), capture_output=True, env=environment, cwd=scratch, timeout=25, check=False)
    require(process.returncode == 0, "hook_process_failed")
    try:
        output = json.loads(process.stdout)
    except (ValueError, UnicodeError):
        raise RuntimeError("hook_output_invalid") from None
    projection = _evidence_for_hook(tenant_id, integration_id, before_ids)
    decision = output.get("hookSpecificOutput", {}).get("permissionDecision")
    projection["hook_decision"] = decision if decision in {"allow", "deny"} else "unknown"
    return projection


ACCEPTANCE_STAGES = frozenset({
    "lab", "schema", "admin_bootstrap", "login", "integration", "signer", "credential",
    "governance_seed", "governance_approval", "restart", "scratch_config", "observation",
    "binding_lookup", "binding_activation", "initial_controls", "binary_acceptance", "enforcement",
    "causal_control_1", "causal_control_2", "causal_hook_0", "causal_hook_1", "causal_hook_2", "validation",
})
ACCEPTANCE_FAILURE_CODES = frozenset({
    "lab_migrations_failed", "migration_0092_missing", "owner_login_failed", "integration_creation_failed",
    "signer_start_failed", "credential_registration_failed", "governance_approval_failed",
    "signed_observation_failed", "observations_lookup_failed", "signed_observation_not_unique",
    "signed_binding_failed", "initial_operation_controls_failed", "binary_acceptance_failed",
    "integration_enforcement_failed", "operation_control_change_failed", "causal_hook_decision_failed",
    "exact_hook_evidence_count_invalid", "hook_process_failed", "hook_output_invalid",
    "signer_scope_invalid", "isolated_schema_not_ready", "causal_phase_count_invalid",
    "causal_decision_mismatch", "causal_authority_missing", "causal_event_hash_invalid",
    "causal_events_not_distinct", "repository_floor_evidence_missing", "scratch_marker_changed",
    "release_readiness_overclaim",
})
FAILURE_SOURCE_FILES = {
    "harness": "infra/scripts/run_isolated_repository_controls_acceptance.py",
    "lab": "infra/scripts/isolated_hawk_lab.py",
    "bootstrap": "infra/scripts/production_bootstrap.py",
    "config": "apps/api/app/core/config.py",
    "repository_service": "apps/api/app/services/github_repository_access_service.py",
}


def acceptance_failure_projection(stage: str, exc: Exception) -> dict:
    require(stage in ACCEPTANCE_STAGES, "acceptance_stage_invalid")
    message = str(exc)
    result = {
        "failure_code": message if message in ACCEPTANCE_FAILURE_CODES else "isolated_acceptance_failed",
        "failure_stage": stage,
        "exception_class": type(exc).__name__ if type(exc).__name__ in DIAGNOSTIC_EXCEPTION_CLASSES | {"KeyError", "TypeError", "AttributeError", "JSONDecodeError", "CalledProcessError"} else None,
        "sqlstate": None,
    }
    cause = exc
    for _ in range(4):
        code = getattr(cause, "pgcode", None) or getattr(cause, "sqlstate", None)
        if code in SQLSTATE_REASONS:
            result["sqlstate"] = code
            break
        cause = getattr(cause, "orig", None) or getattr(cause, "__cause__", None)
        if cause is None:
            break
    frame = exc.__traceback__
    while frame is not None:
        for token, relative in FAILURE_SOURCE_FILES.items():
            if frame.tb_frame.f_code.co_filename == str(ROOT / relative) and 1 <= frame.tb_lineno <= 10000:
                result["source"] = {"source_token": token, "line": frame.tb_lineno}
        frame = frame.tb_next
    return result


def bootstrap_lab_owner(lab, *, on_stage=None) -> dict:
    from production_bootstrap import create_initial_administrator
    # Direct test-fixture bootstrap retains the existing empty-database lock,
    # password validation, role and audit. It makes no production topology claim.
    password = "Aa9!" + secrets.token_urlsafe(48)
    email = "isolated-repository-owner@example.com"
    if on_stage:
        on_stage("admin_bootstrap")
    create_initial_administrator(email=email, full_name="Isolated Repository Owner", tenant_name="Isolated Repository Lab", tenant_slug="isolated-repository-lab", password=password)
    if on_stage:
        on_stage("login")
    status, owner = lab.request("POST", "/auth/login", payload={"email": email, "password": password})
    require(status == 200, "owner_login_failed")
    return owner


PROFILE_FUNCTIONS = {
    ("apps/api/app/services/native_control/envelope.py", "validate_trusted_envelope"): "envelope_validation",
    ("apps/api/app/api/routers/native_controls.py", "claim"): "database_replay_claim",
    ("apps/api/app/api/routers/native_controls.py", "_latest_real_validation_is_bound_to_current_contract"): "real_validation_binding",
    ("apps/api/app/api/routers/native_controls.py", "_latest_validation"): "latest_validation",
    ("apps/api/app/api/routers/native_controls.py", "_active_credential"): "active_credential",
    ("apps/api/app/api/routers/native_controls.py", "_facts"): "integration_facts",
    ("apps/api/app/api/routers/native_controls.py", "_claim_logical_provider_action"): "logical_action_claim",
    ("apps/api/app/api/routers/native_controls.py", "_assert_current_callback_receipt_binding"): "callback_receipt_binding",
    ("apps/api/app/services/github_repository_access_service.py", "resolve_repository_control_floor"): "repository_control_floor",
    ("apps/api/app/services/github_repository_access_service.py", "observe_github_repository_runtime"): "repository_observation",
    ("apps/api/app/services/receipt_service.py", "persist_pre_execution_decision_in_transaction"): "pre_execution_persistence",
    ("apps/api/app/services/receipt_service.py", "create_decision_receipt_from_authorization"): "decision_receipt",
    ("apps/api/app/services/receipt_service.py", "canonical_action_from_authorization"): "canonical_receipt_action",
    ("apps/api/app/services/receipt_service.py", "validate_pre_execution"): "pre_execution_validation",
    ("apps/api/app/services/receipt_service.py", "record_execution_incomplete"): "execution_incomplete",
    ("apps/api/app/services/native_control/route_binding.py", "current_route_surfaces_for_integration"): "route_surfaces",
    ("apps/api/app/api/routers/native_controls.py", "receive_native_callback"): "native_callback",
    ("apps/api/app/api/routers/native_controls.py", "_enrich_native_request_with_discovery_context"): "discovery_enrichment",
    ("apps/api/app/services/native_control/live_adapter_dispatch.py", "dispatch_live_callback_adapter"): "exact_dispatch",
    ("apps/api/app/services/native_control/live_adapter_dispatch.py", "_normalize_hash_only_endpoint_event"): "hash_normalization",
    ("apps/api/app/services/native_control/selection_service.py", "select_and_persist_authorization"): "selection_persistence",
    ("apps/api/app/services/native_control/selection_service.py", "_candidate"): "selection_candidate",
    ("apps/api/app/services/native_control/selection_service.py", "_real_acceptance_rejection_reasons"): "acceptance_eligibility",
    ("apps/api/app/services/native_control/selector.py", "select"): "semantic_selection",
    ("apps/api/app/services/native_control/selector.py", "resolve_control_plan"): "control_plan",
    ("apps/api/app/services/native_control/health.py", "health_snapshot"): "health_measurement",
    ("apps/api/app/services/native_control/health.py", "record_health_observation"): "health_persistence",
    ("apps/api/app/services/native_control/requirements.py", "derive_control_requirements"): "control_requirements",
    ("apps/api/app/core/control_engine/authorization.py", "authorize_ai_action"): "authorization",
    ("apps/api/app/core/control_engine/authorization.py", "apply_authorization_rollout"): "authorization_rollout",
    ("apps/api/app/services/runtime_intelligence/runtime_correlation_service.py", "correlate_runtime_event"): "runtime_correlation",
}


def profile_database_functions() -> dict:
    from sqlalchemy.orm import Session
    functions = {}
    for name in ("scalar", "scalars", "get", "refresh", "flush", "commit", "begin_nested"):
        code = getattr(Session, name).__code__
        functions[(code.co_filename, code.co_firstlineno, code.co_name)] = f"db_{name}"
    return functions


def cold_profile_projection(stats, total_seconds) -> dict:
    allowed = {(str(ROOT / relative), function): token for (relative, function), token in PROFILE_FUNCTIONS.items()}
    database_functions = profile_database_functions()
    def milliseconds(value):
        return round(value * 1000, 2) if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 300 else None
    rows = []
    for key, value in stats.items():
        if not isinstance(key, tuple) or len(key) != 3:
            continue
        token = database_functions.get(key) or allowed.get((key[0], key[2]))
        if token is None:
            continue
        if not isinstance(value, tuple) or len(value) != 5:
            continue
        _, count, own, cumulative, _ = value
        own_ms, cumulative_ms = milliseconds(own), milliseconds(cumulative)
        if type(count) is not int or not 0 <= count <= 1000000 or own_ms is None or cumulative_ms is None:
            continue
        rows.append({"token": token, "call_count": count, "self_ms": own_ms, "cumulative_ms": cumulative_ms})
    rows.sort(key=lambda row: (-row["cumulative_ms"], row["token"]))
    return {"route_total_ms": milliseconds(total_seconds), "functions": rows[:32]}


def profile_first_exact_callback(app, profile_path: Path) -> None:
    from fastapi.routing import APIRoute, _IncludedRouter
    effective_routes = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            effective_routes.append(route)
        elif isinstance(route, _IncludedRouter):
            # FastAPI recursively resolves nested includes into cached contexts
            # used by dispatch; mutating original_route does not wrap that call.
            effective_routes.extend(route.effective_route_contexts())
    routes = [route for route in effective_routes if route.path == "/native-controls/callbacks/{integration_id}" and route.name == "receive_native_callback" and route.dependant is not None]
    require(len(routes) == 1, "cold_profile_route_unavailable")
    route = routes[0]
    original = route.dependant.call
    lock, claimed = threading.Lock(), False
    @functools.wraps(original)
    def wrapped(*args, **kwargs):
        nonlocal claimed
        with lock:
            should_profile = not claimed
            claimed = True
        if not should_profile:
            return original(*args, **kwargs)
        profiler = cProfile.Profile()
        try:
            profiler.enable()
            return original(*args, **kwargs)
        finally:
            profiler.disable()
            profiler.dump_stats(str(profile_path))
    route.dependant.call = wrapped


def serve_cold_profile_api(port: int, profile_path: Path) -> None:
    from app.main import app
    import uvicorn
    profile_first_exact_callback(app, profile_path)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)


def cold_profile_lab(root: Path):
    from isolated_hawk_lab import IsolatedHawkLab, PYTHON
    class ProfileLab(IsolatedHawkLab):
        def _spawn(self, label, command, *, component=None):
            if label == "api":
                command = [str(PYTHON), str(Path(__file__).resolve()), "--serve-cold-profile-api", str(self.ports["api"]), "--private-profile", str(self.root / "cold-callback.prof")]
            super()._spawn(label, command, component=component)
    return ProfileLab(root, extra_env=acceptance_lab_flags())


def run_acceptance(root: Path, *, cold_profile: bool = False) -> dict:
    from isolated_hawk_lab import IsolatedHawkLab
    report = {"signer": "software_test_only", "release_ready": False, "strict_health": False, "migration_0092": False, "phases": []}
    lab = cold_profile_lab(root) if cold_profile else IsolatedHawkLab(root, extra_env=acceptance_lab_flags())
    if cold_profile:
        report.update({"profiling_overhead": True, "acceptance_evidence": False})
    signer = None
    signer_socket = root / "software-signer.sock"
    stage = "lab"
    def set_stage(value):
        nonlocal stage
        stage = value
    try:
        lab.prepare()
        lab.start()
        report["strict_health"] = True
        stage = "schema"
        from sqlalchemy import text
        from app.db.session import SessionLocal
        with SessionLocal() as db:
            head = db.scalar(text("SELECT version_num FROM alembic_version"))
            schema = db.scalar(text("SELECT to_regclass('public.github_repository_runtime_bindings') IS NOT NULL"))
            report["migration_0092"] = head == "0092_github_repository_runtime_controls" and schema is True
        require(report["migration_0092"], "migration_0092_missing")
        stage = "admin_bootstrap"
        registered = bootstrap_lab_owner(lab, on_stage=set_stage)
        tenant_id = registered["tenants"][0]["id"]
        headers = {"Authorization": "Bearer " + registered["access_token"], "X-Tenant-ID": tenant_id}
        now = datetime.now(timezone.utc)
        stage = "integration"
        status, integration = lab.request("POST", "/native-controls/integrations", headers=headers, payload={"provider": "anthropic", "product": "claude_code", "method": "native_hook", "instance_key": "isolated-repository-hook", "display_name": "Isolated repository hook", "environment": "production", "deployment_family": "endpoint", "provider_version": "2.1.183", "adapter_version": "1.2.0", "policy_version": "policy-repository-floor", "policy_fresh_until": (now + timedelta(hours=1)).isoformat(), "degradation_mode": "fail_closed", "trusted_workload_authority": True})
        require(status == 201, "integration_creation_failed")
        integration_id = integration["id"]
        stage = "signer"
        signer = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve-software-signer", str(signer_socket)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=lab.env)
        require(signer.stdout is not None, "signer_start_failed")
        public_identity = json.loads(signer.stdout.readline(8192))
        stage = "credential"
        status, _ = lab.request("POST", f"/native-controls/integrations/{integration_id}/credentials", headers=headers, payload={"credential_id": "isolated-repository-workload", "credential_epoch": 1, "public_key_pem": public_identity["public_key_pem"], "environment": "production", "allowed_event_types": ["before_tool"], "expires_at": (now + timedelta(hours=1)).isoformat()})
        require(status == 201, "credential_registration_failed")
        stage = "governance_seed"
        repository_id, assignment_id = seed_current_repository(tenant_id, now)
        repo_path = f"/control-coverage/source-control/github-repositories/repositories/{repository_id}"
        stage = "governance_approval"
        status, _ = lab.request("PUT", repo_path + "/governance", headers=headers, payload={"decision": "APPROVED", "expected_governance_version": 0, "assignment_id": assignment_id})
        require(status == 200, "governance_approval_failed")
        stage = "restart"
        lab.env.update({"AUTHORIZATION_KERNEL_V2_ENFORCE": "true", "AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT": json.dumps({tenant_id: ["runtime_control"]}), "DECISION_EXECUTION_RECEIPTS_ENABLED": "true", "RECEIPT_SIGNING_ACTIVE_KEY_ID": "isolated-repository-receipt", "RECEIPT_SIGNING_KEYS_JSON": json.dumps({"isolated-repository-receipt": secrets.token_urlsafe(32)}), "NATIVE_CONTROL_ROUTE_BINDINGS_JSON": json.dumps({tenant_id: {"runtime_control": {"integration_instance_ids": [integration_id], "provider": "anthropic", "product": "claude_code", "provider_version": "2.1.183", "adapter_version": "1.2.0"}}})})
        lab.restart_api()
        stage = "scratch_config"
        scratch = root / "scratch-repository"
        scratch.mkdir(mode=0o700)
        subprocess.run(["git", "init", "-q", str(scratch)], capture_output=True, check=True, env={key: value for key, value in lab.env.items() if not key.startswith("GIT_")})
        marker = scratch / "README.md"
        marker.write_text("Synthetic local repository marker.\n")
        marker_hash = hashlib.sha256(marker.read_bytes()).hexdigest()
        config = root / "hook-config.json"
        config.write_text(json.dumps({"api_url": lab.base_url, "tenant_id": tenant_id, "integration_id": integration_id, "credential_id": "isolated-repository-workload", "credential_epoch": 1, "provider": "anthropic", "product": "claude_code", "provider_version": "2.1.183", "adapter_version": "1.2.0", "environment": "production", "key_provider": "kms_hsm_helper", "security_profile": "development", "kms_hsm_helper_path": "unix://" + str(signer_socket), "kms_hsm_key_reference": "kms://isolated-software-test"}))
        config.chmod(0o600)
        stage = "observation"
        observation = run_hook(lab, config, scratch, tenant_id, integration_id, "observation")
        require(observation["hook_decision"] == "allow" and observation["authenticated"] and observation["exact_adapter"], "signed_observation_failed")
        if cold_profile:
            stage = "validation"
            stats = pstats.Stats(str(root / "cold-callback.prof"))
            report["cold_profile"] = cold_profile_projection(stats.stats, stats.total_tt)
            report["status"] = "profiled"
            return report
        stage = "binding_lookup"
        status, observed = lab.request("GET", "/control-coverage/source-control/github-repositories/runtime-bindings", headers=headers)
        require(status == 200, "observations_lookup_failed")
        candidates = [row for row in observed["items"] if row["native_integration_id"] == integration_id and row["state"] == "OBSERVED" and row["scope"] == "EXACT_FOLDER" and row["repository_id"] is None]
        require(len(candidates) == 1, "signed_observation_not_unique")
        stage = "binding_activation"
        status, binding = lab.request("PUT", repo_path + "/runtime-binding", headers=headers, payload={"observation_id": candidates[0]["id"], "expected_governance_version": 1})
        require(status == 200 and binding.get("state") == "ACTIVE", "signed_binding_failed")
        all_allowed = {key: "ALLOW" for key in ("READ", "EDIT", "COMMIT", "PULL", "PUSH")}
        stage = "initial_controls"
        status, _ = lab.request("PUT", repo_path + "/operation-controls", headers=headers, payload={"controls": all_allowed, "expected_governance_version": 2})
        require(status == 200, "initial_operation_controls_failed")
        stage = "binary_acceptance"
        status, accepted = lab.request("POST", f"/native-controls/integrations/{integration_id}/accept-real-binary", headers=headers)
        require(status == 200 and accepted.get("acceptance_state") == "REAL_BINARY_ACCEPTED" and accepted.get("result") == "passed", "binary_acceptance_failed")
        stage = "enforcement"
        status, enforced = lab.request("POST", f"/native-controls/integrations/{integration_id}/enforce", headers=headers)
        require(status == 200 and enforced.get("state") == "enforcing" and enforced.get("authoritative") is True, "integration_enforcement_failed")
        for index, expected in enumerate(("allow", "block", "allow")):
            if index:
                stage = f"causal_control_{index}"
                controls = {**all_allowed, "READ": "BLOCK" if expected == "block" else "ALLOW"}
                status, _ = lab.request("PUT", repo_path + "/operation-controls", headers=headers, payload={"controls": controls, "expected_governance_version": 2 + index})
                require(status == 200, "operation_control_change_failed")
            stage = f"causal_hook_{index}"
            phase = run_hook(lab, config, scratch, tenant_id, integration_id, f"causal-{index}")
            report["phases"].append(phase)
            require(phase["decision"] == expected, "causal_hook_decision_failed")
        stage = "validation"
        report["scratch_unchanged"] = hashlib.sha256(marker.read_bytes()).hexdigest() == marker_hash
        report["scratch_marker_sha256"] = marker_hash
        report["workspace_hash"] = binding["canonical_root_sha256"]
        report["common_dir_hash"] = binding["common_dir_sha256"]
        sources = {"router": "apps/api/app/api/routers/native_controls.py", "repository_service": "apps/api/app/services/github_repository_access_service.py", "hook": "apps/endpoint-agent/src/hawk_endpoint_agent/native_control/hook.py", "classifier": "apps/endpoint-agent/src/hawk_endpoint_agent/native_control/repository_guard.py", "migration": "apps/api/app/db/migrations/versions/0092_github_repository_runtime_controls.py", "ui": "apps/web/src/app/control-coverage/source-control/github-repository-boundary/page.tsx", "harness": "infra/scripts/run_isolated_repository_controls_acceptance.py"}
        report["source_sha256"] = {name: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() for name, relative in sources.items()}
        validate_report(report)
        report["status"] = "passed"
        return report
    except Exception as exc:
        report["status"] = "blocked"
        report.update(acceptance_failure_projection(stage, exc))
        return report
    finally:
        if signer is not None:
            signer.terminate()
            try:
                signer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signer.kill()
                signer.wait(timeout=5)
        signer_socket.unlink(missing_ok=True)
        lab.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve-software-signer", type=Path)
    parser.add_argument("--diagnose-migrations", action="store_true")
    parser.add_argument("--cold-profile", action="store_true")
    parser.add_argument("--serve-cold-profile-api", type=int)
    parser.add_argument("--private-profile", type=Path)
    parser.add_argument("--evidence-file", type=Path)
    args = parser.parse_args()
    if args.serve_cold_profile_api is not None:
        if args.private_profile is None:
            parser.error("private profile required")
        serve_cold_profile_api(args.serve_cold_profile_api, args.private_profile)
        return 0
    if args.serve_software_signer:
        serve_software_signer(args.serve_software_signer)
        return 0
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="hawk-repository-controls-", dir="/private/tmp") as name:
            report = run_migration_diagnostic(Path(name)) if args.diagnose_migrations else run_acceptance(Path(name), cold_profile=True) if args.cold_profile else run_acceptance(Path(name))
        # Publication happens only after cleanup succeeds. A cleanup failure
        # must not leave a success report alongside retained private state.
        evidence_file = args.evidence_file or ROOT / ("docs/evidence/repository-runtime-migration-diagnostic.json" if args.diagnose_migrations else "docs/evidence/repository-runtime-cold-profile.json" if args.cold_profile else "docs/evidence/repository-runtime-controls.json")
        evidence_file.parent.mkdir(parents=True, exist_ok=True)
        evidence_file.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] in {"passed", "profiled"} else 1
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
