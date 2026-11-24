from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest


def _harness():
    path = Path(__file__).resolve().parents[1] / "scripts/run_isolated_repository_controls_acceptance.py"
    spec = importlib.util.spec_from_file_location("repository_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report():
    return {
        "signer": "software_test_only", "release_ready": False,
        "strict_health": True, "migration_0092": True, "scratch_unchanged": True,
        "phases": [
            {"decision": decision, "hook_decision": "deny" if decision == "block" else "allow",
             "enforced": True, "exact_adapter": True, "authenticated": True,
             "lifecycle_before_tool": True, "provider_event_hash": str(index + 1) * 64,
             "reason_codes": ["repository_control_floor", "repository_operation_blocked"] if decision == "block" else []}
            for index, decision in enumerate(("allow", "block", "allow"))
        ],
    }


def test_callback_projection_discards_private_material_and_unbounded_codes():
    harness = _harness()
    payload = {"decision": "block", "enforced": True, "adapter_dispatch": "exact",
               "provider_event_id_hash": "a" * 64,
               "reason_codes": ["repository_operation_blocked", "/private/synthetic-path"],
               "credentials": "private-synthetic-token", "target": "/private/synthetic-path",
               "signature": "private-synthetic-signature", "provider_payload": {"prompt": "private-synthetic-prompt"}}
    result = harness.callback_projection(payload, lifecycle="before_tool", signal="authenticated_native_adapter")
    assert result["reason_codes"] == ["repository_operation_blocked"]
    assert "private-synthetic" not in json.dumps(result)
    assert "/private/" not in json.dumps(result)
    assert result["authenticated"] is True


def test_causal_report_requires_exact_distinct_authenticated_enforced_events():
    harness = _harness()
    harness.validate_report(_report())
    for field in ("enforced", "exact_adapter", "authenticated", "lifecycle_before_tool"):
        report = _report()
        report["phases"][1][field] = False
        with pytest.raises(RuntimeError, match="causal_authority_missing"):
            harness.validate_report(report)
    report = _report()
    report["phases"][2]["provider_event_hash"] = report["phases"][0]["provider_event_hash"]
    with pytest.raises(RuntimeError, match="causal_events_not_distinct"):
        harness.validate_report(report)


def test_causal_report_cannot_overclaim_signer_or_release_readiness():
    harness = _harness()
    report = _report()
    report["signer"] = "hardware"
    with pytest.raises(RuntimeError, match="signer_scope_invalid"):
        harness.validate_report(report)
    report = _report()
    report["release_ready"] = True
    with pytest.raises(RuntimeError, match="release_readiness_overclaim"):
        harness.validate_report(report)
    report = _report()
    report["phases"][1]["reason_codes"] = []
    with pytest.raises(RuntimeError, match="repository_floor_evidence_missing"):
        harness.validate_report(report)


@pytest.mark.parametrize("status,exit_code", [("passed", 0), ("blocked", 1)])
@pytest.mark.parametrize("diagnostic", ["acceptance", "migrations", "cold_profile"])
def test_main_removes_private_lab_before_publishing_success_or_blocked_evidence(tmp_path, monkeypatch, status, exit_code, diagnostic):
    harness = _harness()
    roots = []
    evidence = tmp_path / "evidence.json"

    def stub_acceptance(root, **kwargs):
        roots.append(root)
        (root / "postgres-password").write_text("private-cleanup-test-secret")
        (root / "logs").mkdir()
        (root / "logs" / "api.log").write_text("private-cleanup-test-log")
        (root / "cold-callback.prof").write_bytes(b"private-cleanup-test-profile")
        return {"status": status, "signer": "software_test_only", "release_ready": False}

    write_text = Path.write_text

    def checked_write(path, *args, **kwargs):
        if path == evidence:
            assert roots and not roots[0].exists()
        return write_text(path, *args, **kwargs)

    monkeypatch.setattr(harness, "run_acceptance", stub_acceptance)
    monkeypatch.setattr(harness, "run_migration_diagnostic", stub_acceptance)
    flags = {"acceptance": [], "migrations": ["--diagnose-migrations"], "cold_profile": ["--cold-profile"]}
    monkeypatch.setattr(harness.sys, "argv", ["repository-acceptance", "--evidence-file", str(evidence)] + flags[diagnostic])
    monkeypatch.setattr(Path, "write_text", checked_write)
    assert harness.main() == exit_code
    assert not roots[0].exists()
    assert json.loads(evidence.read_text())["status"] == status
    assert "private-cleanup-test" not in evidence.read_text()


def test_migration_diagnostic_projects_only_closed_error_revision_and_sqlstate():
    harness = _harness()
    private_log = "private-token /private/owned-log-path\nINFO Running upgrade 0091_exec_mcp_device_auth -> 0092_github_repository_runtime_controls, private-prompt\n"
    private_log += "HAWK_DIAGNOSTIC_FACTS=" + json.dumps({"exception_class": "DataError", "sqlstate": "22001", "credentials": "private-token"})
    result = harness.diagnostic_projection("migrations", private_log, passed=False)
    assert result == {
        "stage": "migrations", "status": "blocked", "exception_class": "DataError",
        "allowlisted_reason_codes": ["migration_value_too_long", "migrations_failed"],
        "sqlstate": "22001", "revision": "0092_github_repository_runtime_controls",
    }
    assert "private" not in json.dumps(result)
    hostile = "HAWK_DIAGNOSTIC_FACTS=" + json.dumps({"exception_class": "private-token", "sqlstate": "private-token"})
    result = harness.diagnostic_projection("settings", hostile, passed=False)
    assert result["exception_class"] is None and result["sqlstate"] is None
    assert result["allowlisted_reason_codes"] == ["settings_failed"]


def test_migration_diagnostic_preserves_exact_acceptance_flags_and_default_topology():
    harness = _harness()
    flags = harness.acceptance_lab_flags()
    binding_key = flags.pop("CANONICAL_ACTION_BINDING_KEY")
    assert len(binding_key) >= 32
    assert binding_key != harness.acceptance_lab_flags()["CANONICAL_ACTION_BINDING_KEY"]
    assert flags == {
        "NATIVE_CONTROL_ADAPTER_FRAMEWORK": "true", "NATIVE_CONTROL_REFERENCE_ADAPTERS": "true",
        "NATIVE_CONTROL_ADAPTER_ENFORCEMENT": "true", "CONTROL_CAPABILITY_MATRIX": "true",
        "NATIVE_CONTROL_MONITOR": "true", "NATIVE_CONTROL_ENFORCE": "true",
        "NATIVE_CONTROL_ANTHROPIC": "true", "AUTHORIZATION_KERNEL_V2_ENABLED": "true",
        "AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED": "true", "DISCOVERY_CONTEXT_PROVIDER": "true",
        "ENV": "production",
        "SELF_REGISTRATION_ENABLED": "false",
    }
    assert "DEPLOYMENT_TOPOLOGY" not in flags


@pytest.mark.parametrize("with_binding_key", [False, True])
def test_settings_preflight_requires_private_canonical_key(tmp_path, with_binding_key):
    harness = _harness()
    flags = harness.acceptance_lab_flags()
    application_secrets = {name: secrets.token_urlsafe(48) for name in (
        "SECRET_KEY", "CONNECTOR_SECRETS_KEY", "CONNECTOR_SECRETS_KDF_SALT", "ONPREM_BUNDLE_SIGNING_SECRET",
    )}
    assert all(flags["CANONICAL_ACTION_BINDING_KEY"] != value for value in application_secrets.values())
    if not with_binding_key:
        flags.pop("CANONICAL_ACTION_BINDING_KEY")
    environment = {
        **{key: os.environ[key] for key in ("PATH", "HOME", "LANG") if key in os.environ},
        **application_secrets, **flags,
        "PYTHONPATH": str(harness.ROOT / "apps/api"), "PYTHONDONTWRITEBYTECODE": "1",
        "SECRET_KEY_LOCK_ENABLED": "true", "SECRET_KEY_LOCK_FILE": str(tmp_path / "secret-key.lock"),
        "SECRET_KEY_LOCK_PEPPER": secrets.token_urlsafe(32),
        "NATIVE_CONTROL_FRAMEWORK": "true", "TRUSTED_CONTROL_SELECTOR": "true",
        "DEPLOYMENT_TOPOLOGY": "development",
    }
    result = subprocess.run(
        [str(harness.ROOT / "apps/api/.venv/bin/python"), "-c", harness._diagnostic_child_program("settings")],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30,
    )
    projection = harness.diagnostic_projection("settings", result.stdout + result.stderr, passed=result.returncode == 0)
    assert projection["status"] == ("passed" if with_binding_key else "blocked")
    assert ("canonical_action_binding_key_missing" in projection["allowlisted_reason_codes"]) is (not with_binding_key)
    assert all(value not in json.dumps(projection) for value in application_secrets.values())
    assert flags.get("CANONICAL_ACTION_BINDING_KEY", "not-a-key") not in json.dumps(projection)


def test_owner_bootstrap_uses_existing_bootstrap_then_public_login_without_secret_output(monkeypatch, capsys):
    harness = _harness()
    calls = []
    def bootstrap(**kwargs):
        calls.append(("bootstrap", kwargs))
    monkeypatch.setitem(sys.modules, "production_bootstrap", SimpleNamespace(create_initial_administrator=bootstrap))
    def request(method, route, *, payload):
        calls.append((route, payload))
        return 200, {"tenants": [{"id": "synthetic-tenant"}], "access_token": "synthetic-access-token"}
    owner = harness.bootstrap_lab_owner(SimpleNamespace(request=request))
    assert [name for name, _ in calls] == ["bootstrap", "/auth/login"]
    password = calls[0][1]["password"]
    assert len(password) >= 32 and any(character.isupper() for character in password)
    assert any(character.islower() for character in password) and any(character.isdigit() for character in password)
    assert "!" in password and calls[1][1]["password"] == password
    assert "password" not in owner
    captured = capsys.readouterr()
    assert not captured.out and not captured.err
    projection = harness.diagnostic_projection("settings", "SELF_REGISTRATION_ENABLED requires a recognized dev, test, or demo ENV and cannot be combined with PILOT_MODE.", passed=False)
    assert "self_registration_environment_invalid" in projection["allowlisted_reason_codes"]
    assert password not in json.dumps(projection)


def test_acceptance_failure_projection_closes_hostile_material_and_stages():
    harness = _harness()
    secret = "private-token /private/path prompt credential signature tenant-id"
    exc = RuntimeError(secret)
    exc.sqlstate = "23503"
    result = harness.acceptance_failure_projection("governance_seed", exc)
    assert result == {"failure_code": "isolated_acceptance_failed", "failure_stage": "governance_seed", "exception_class": "RuntimeError", "sqlstate": "23503"}
    assert "private" not in json.dumps(result)
    assert harness.acceptance_failure_projection("observation", RuntimeError("hook_process_failed"))["failure_code"] == "hook_process_failed"
    with pytest.raises(RuntimeError, match="acceptance_stage_invalid"):
        harness.acceptance_failure_projection(secret, exc)


def test_acceptance_failure_projection_emits_only_fixed_source_frame_and_releases_traceback(tmp_path):
    harness = _harness()
    filename = str(harness.ROOT / harness.FAILURE_SOURCE_FILES["harness"])
    namespace = {}
    exec(compile("def fail():\n    raise ValueError('private-frame-secret')\n", filename, "exec"), namespace)
    try:
        namespace["fail"]()
    except ValueError as exc:
        result = harness.acceptance_failure_projection("signer", exc)
    assert result["source"] == {"source_token": "harness", "line": 2}
    assert set(result) == {"failure_code", "failure_stage", "exception_class", "sqlstate", "source"}
    assert "private" not in json.dumps(result) and filename not in json.dumps(result)
    # The projection owns scalar facts only; it can be published after root cleanup.
    root = tmp_path / "owned-root"
    root.mkdir()
    root.rmdir()
    assert not root.exists()
    assert json.loads(json.dumps(result)) == result


def test_repository_seed_commits_complete_tenant_scoped_foreign_key_chain(tmp_path, monkeypatch):
    harness = _harness()
    monkeypatch.syspath_prepend(str(harness.ROOT / "apps/api"))
    monkeypatch.setattr(os, "environ", os.environ.copy())
    from app.core.test_settings import apply_test_settings
    apply_test_settings()
    from sqlalchemy import create_engine, event, select, text
    from sqlalchemy.orm import sessionmaker
    from app.db.session import Base
    import app.db.models
    from app.db.models.tenant import Tenant
    from app.db.models.ai_asset import DiscoveryAIAsset
    from app.db.models.github_repository_access import GitHubRepository
    from app.db.models.policy_pack_platform import PolicyPackAssignment
    from app.db.models.capability_inference import DiscoveryCapabilityGenome, DiscoveryCapabilityInferenceRun
    from app.db.models.evidence import EvidenceNode
    from app.db.models.discovery_resolution import DiscoveryAssetHypothesis
    from app.db.models.evidence_resolution import DiscoveryHypothesisEvaluation, DiscoveryEcosystemMembership
    from app.db.models.discovery_verification import DiscoveryVerificationAssertion, DiscoveryVerificationEpisode, DiscoveryVerificationPolicy
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'seed.sqlite3'}")
    @event.listens_for(engine, "connect")
    def enforce_foreign_keys(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
    factory = sessionmaker(bind=engine)
    try:
        Base.metadata.create_all(engine)
        with factory() as db:
            tenant = Tenant(name="Synthetic Repository Lab", slug="synthetic-repository-lab", is_active=True)
            db.add(tenant)
            db.commit()
            tenant_id = tenant.id
        repository_id, assignment_id = harness.seed_current_repository(tenant_id, datetime.now(timezone.utc), session_factory=factory)
        with factory() as db:
            assert db.scalar(text("PRAGMA foreign_keys")) == 1
            seeded_tables = (
                "tenants", "github_source_organizations", "github_repositories",
                "policy_packs", "policy_versions", "policy_pack_definitions", "policy_pack_instances", "policy_pack_assignments",
                "evidence_nodes", "discovery_ai_assets", "discovery_resolution_graph_nodes",
                "discovery_capability_inference_runs", "discovery_capability_genomes",
                "discovery_asset_hypotheses", "discovery_hypothesis_evaluations",
                "discovery_ai_ecosystems", "discovery_ecosystem_memberships",
                "discovery_verification_policies", "discovery_verification_episodes", "discovery_verification_assertions",
            )
            for table in seeded_tables:
                assert db.execute(text(f"PRAGMA foreign_key_check('{table}')")).all() == []
            assert db.get(GitHubRepository, repository_id).tenant_id == tenant_id
            assert db.get(PolicyPackAssignment, assignment_id).tenant_id == tenant_id
            genome = db.scalar(select(DiscoveryCapabilityGenome))
            run = db.get(DiscoveryCapabilityInferenceRun, genome.inference_run_id)
            membership = db.scalar(select(DiscoveryEcosystemMembership))
            assertion = db.scalar(select(DiscoveryVerificationAssertion))
            episode = db.get(DiscoveryVerificationEpisode, assertion.episode_id)
            evaluation = db.get(DiscoveryHypothesisEvaluation, assertion.erg_evaluation_id)
            hypothesis = db.get(DiscoveryAssetHypothesis, evaluation.hypothesis_id)
            policy = db.get(DiscoveryVerificationPolicy, assertion.policy_record_id)
            evidence = db.get(EvidenceNode, run.evidence_node_id)
            asset = db.scalar(select(DiscoveryAIAsset))
            assert all(row.tenant_id == tenant_id for row in (genome, run, membership, assertion, episode, evaluation, hypothesis, policy, evidence))
            assert run.inference_run_id == evaluation.inference_run_id
            assert run.evidence_node_id == membership.evidence_node_id == hypothesis.evidence_node_id
            assert asset.tenant_id == tenant_id and asset.evidence_bundle_id == evidence.id
            assert evidence.node_type == "evidence_bundle" and evidence.payload["synthetic"] is True
            assert episode.hypothesis_evaluation_id == evaluation.evaluation_id
            assert episode.policy_record_id == policy.policy_record_id
            assert episode.ecosystem_record_id == membership.ecosystem_record_id == assertion.ecosystem_record_id
    finally:
        engine.dispose()


@pytest.mark.parametrize("assurance,expected", [(-1, None), (6, None), (True, None), (2.5, None), ("private-key", None), (0, 0), (5, 5)])
def test_selector_projection_filters_hostile_data_and_bounds_numeric_fields(monkeypatch, assurance, expected):
    harness = _harness()
    monkeypatch.syspath_prepend(str(harness.ROOT / "apps/api"))
    monkeypatch.setattr(os, "environ", os.environ.copy())
    from app.core.test_settings import apply_test_settings
    apply_test_settings()
    from app.services.native_control.contracts import CapabilityDimension
    capability = next(iter(CapabilityDimension)).value
    private = "private-token /private/path provider-payload"
    selection = SimpleNamespace(
        required_capabilities=[capability, private, {"secret": private}],
        satisfied_capabilities=[capability], unsatisfied_capabilities=[private],
        assurance_level=assurance, selection_reason="CONTROL_REQUIREMENT_UNSATISFIED",
        control_plan_reason_codes=[private, "minimum_assurance_unsatisfied"],
        rejected_candidates=[{"reason_codes": ["deployment_acceptance_lifecycle_mismatch", private], "payload": private}] * 200,
        rejected_mandatory_floor_candidates={private: [{"reason_codes": ["mandatory_enforcement_floor_unsatisfied", private]}]},
    )
    result = harness.selector_projection(selection)
    assert result["required_capabilities"] == result["satisfied_capabilities"] == [capability]
    assert result["unsatisfied_capabilities"] == []
    assert result["assurance_level"] == expected and result["required_assurance"] is None
    assert result["rejected_candidate_count"] == 128
    assert result["selected_reason_codes"] == ["CONTROL_REQUIREMENT_UNSATISFIED", "minimum_assurance_unsatisfied"]
    assert result["rejected_reason_codes"] == ["deployment_acceptance_lifecycle_mismatch", "mandatory_enforcement_floor_unsatisfied"]
    assert "private" not in json.dumps(result)
    assert harness.selector_projection(None) == {"status": "not_found"}


def test_latency_projection_bounds_samples_and_discards_private_material():
    harness = _harness()
    result = harness.latency_projection(["private-token /private/path", True, -1, 300001, None, 2.5, 300000, 0, 25], 300000, 250)
    assert result == {
        "sample_count": 3, "latency_samples_ms": [0, 25, 300000],
        "minimum_ms": 0, "maximum_ms": 300000,
        "health_p95_ms": 300000, "requirement_budget_ms": 250, "p95_exceeds_budget": True,
    }
    assert "private" not in json.dumps(result)
    capped = harness.latency_projection(list(range(600)), 250, 250)
    assert capped["sample_count"] == 500 and capped["latency_samples_ms"] == list(range(16))
    assert capped["maximum_ms"] == 499 and capped["p95_exceeds_budget"] is False
    invalid = harness.latency_projection([], "private-key", True)
    assert invalid["health_p95_ms"] is invalid["requirement_budget_ms"] is invalid["p95_exceeds_budget"] is None
    assert invalid["minimum_ms"] is invalid["maximum_ms"] is None


def test_cold_profile_wraps_first_effective_nested_callback_through_installed_fastapi(tmp_path):
    harness = _harness()
    from fastapi import FastAPI, APIRouter
    from fastapi.testclient import TestClient
    app = FastAPI()
    parent, nested = APIRouter(), APIRouter()
    calls = []
    @app.get("/health")
    def health():
        calls.append("health")
        return "healthy"
    @nested.post("/{integration_id}")
    def receive_native_callback(integration_id: str):
        calls.append(integration_id)
        return "callback"
    parent.include_router(nested, prefix="/callbacks")
    app.include_router(parent, prefix="/native-controls")
    profile = tmp_path / "private.prof"
    harness.profile_first_exact_callback(app, profile)
    with TestClient(app) as client:
        assert client.get("/health").json() == "healthy" and not profile.exists()
        assert client.post("/native-controls/callbacks/first").json() == "callback"
        first = profile.read_bytes()
        assert client.post("/native-controls/callbacks/second").json() == "callback"
        assert profile.read_bytes() == first and calls == ["health", "first", "second"]


def test_cold_profile_projection_filters_hostile_pstats_and_bounds_rows():
    harness = _harness()
    relative, function = next(iter(harness.PROFILE_FUNCTIONS))
    filename = str(harness.ROOT / relative)
    stats = {(filename, line, function): (1, 2, 0.001234, 0.2, {"private-path-secret": "private-data"}) for line in range(50)}
    stats[("/private/token", 1, "private-function")] = (1, 1, 1, 1, {})
    stats[(filename, 100, function)] = (1, 1000001, 1, 1, {})
    stats[(filename, 101, function)] = (1, True, 1, 1, {})
    stats[(filename, 102, function)] = (1, 1, float("nan"), 1, {})
    stats[(filename, 103, function)] = (1, 1, -1, 1, {})
    result = harness.cold_profile_projection(stats, 0.395678)
    stats[(filename, 104, "private-function-name")] = (1, 1, 1, 1, {})
    assert harness.cold_profile_projection({(filename, 104, "private-function-name"): (1, 1, 1, 1, {})}, 1)["functions"] == []
    assert result["route_total_ms"] == 395.68 and len(result["functions"]) == 32
    assert all(row == {"token": harness.PROFILE_FUNCTIONS[(relative, function)], "call_count": 2, "self_ms": 1.23, "cumulative_ms": 200.0} for row in result["functions"])
    assert "private" not in json.dumps(result) and filename not in json.dumps(result)
    assert harness.cold_profile_projection({}, 301)["route_total_ms"] is None


def test_profile_database_tokens_match_only_installed_session_code_objects():
    harness = _harness()
    database = harness.profile_database_functions()
    assert set(database.values()) == {"db_scalar", "db_scalars", "db_get", "db_refresh", "db_flush", "db_commit", "db_begin_nested"}
    stats = {key: (1, 3, 0.001, 0.002, {"SQL private-parameter": "private-token"}) for key in database}
    key = next(iter(database))
    stats[(key[0], key[1] + 1, key[2])] = (1, 100, 1, 1, {})
    stats[("/private/sqlalchemy/session.py", key[1], key[2])] = (1, 100, 1, 1, {})
    result = harness.cold_profile_projection(stats, 0.01)
    assert len(result["functions"]) == 7
    assert {row["token"] for row in result["functions"]} == set(database.values())
    assert all(row["call_count"] == 3 for row in result["functions"])
    assert "private" not in json.dumps(result) and "SQL" not in json.dumps(result)
