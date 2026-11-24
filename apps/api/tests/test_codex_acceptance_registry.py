from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.services.native_control.codex_acceptance_registry import (
    load_codex_acceptance_registry,
)


BINARY_SHA256 = "4f85982624b3898c8991cb80c0981b2aa71070e3537046c9a95950318a95afcc"


def _write_fixture(repository: Path) -> tuple[Path, Path]:
    evidence = repository / "docs" / "evidence"
    evidence.mkdir(parents=True)
    report_path = evidence / "codex-0.154.0-acceptance-result.json"
    report = {
        "schema_version": "hawk.codex.acceptance-result/1.0",
        "classification": "real_binary_isolated_hardware_signed_callback_acceptance",
        "provider": "openai",
        "product": "codex",
        "provider_version": "0.154.0",
        "adapter_version": "1.0.0",
        "binary_sha256": BINARY_SHA256,
        "evidence_timestamp": "2026-10-05T19:00:00+00:00",
        "platform": "macos-arm64",
        "scope": {
            "provider_adapter_contract_verified": True,
            "tenant_deployment_accepted": False,
            "live_backend_signature_verified": False,
            "synthetic_fixture": False,
        },
        "result": {
            "passed": True,
            "actual_binary_executed": True,
            "binary_hash_verified": True,
            "exact_version_verified": True,
            "version_command_succeeded": True,
            "hardware_backed_key": True,
            "hardware_key_provider": "macos_secure_enclave",
            "key_thumbprint": "b" * 64,
            "signature_algorithm": "ES256",
            "allow_callback_observed": True,
            "allow_signature_verified": True,
            "prompt_hook_observed": True,
            "block_signature_verified": True,
            "prompt_blocked_before_model": True,
            "raw_prompt_exported": False,
            "hook_installation_observed": True,
            "isolated_hook_trust_bypass": True,
            "model_transport_isolated": True,
            "model_request_observed": False,
            "tested_events": ["session_start", "before_model"],
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    registry_path = evidence / "codex-acceptance-registry.json"
    registry = {
        "schema_version": "hawk.codex.acceptance-registry/1.0",
        "entries": [
            {
                "provider": "openai",
                "product": "codex",
                "provider_version": "0.154.0",
                "adapter_version": "1.0.0",
                "binary_sha256": BINARY_SHA256,
                "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "evidence_artifact": "docs/evidence/codex-0.154.0-acceptance-result.json",
                "evidence_timestamp": "2026-10-05T19:00:00+00:00",
                "platform": "macos-arm64",
                "tested_events": ["session_start", "before_model"],
                "accepted_capabilities": ["discovery", "identity", "prompt_control"],
                "measured_callback_p95_ms": 12.5,
                "reviewed": True,
                "review_status": "reviewed_by_acceptance_gate",
                "production_eligible": True,
            }
        ],
    }
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry_path, report_path


def test_codex_registry_accepts_only_the_exact_hash_bound_contract(tmp_path: Path) -> None:
    registry_path, _report_path = _write_fixture(tmp_path / "repo")
    registry = load_codex_acceptance_registry(registry_path)

    assert registry.accepted_versions(adapter_version="1.0.0") == ("0.154.0",)
    assert registry.assurance("0.154.0", adapter_version="1.0.0") == "exact_verified"
    assert registry.assurance("0.155.0", adapter_version="1.0.0") == "unsupported"
    entry = registry.entry("0.154.0", adapter_version="1.0.0")
    assert entry is not None
    assert entry.binary_sha256 == BINARY_SHA256
    assert entry.accepted_capabilities == ("discovery", "identity", "prompt_control")


def test_codex_registry_rejects_missing_mismatched_or_synthetic_evidence(tmp_path: Path) -> None:
    mutations = (
        ("registry", "report_sha256", "0" * 64),
        ("registry", "binary_sha256", "1" * 64),
        ("registry", "provider_version", "0.155.0"),
        ("registry", "production_eligible", False),
        ("report_scope", "tenant_deployment_accepted", True),
        ("report_scope", "synthetic_fixture", True),
        ("report_result", "allow_signature_verified", False),
        ("report_result", "prompt_blocked_before_model", False),
        ("report_result", "model_transport_isolated", False),
        ("report_result", "model_request_observed", True),
    )
    for index, (target, field, value) in enumerate(mutations):
        registry_path, report_path = _write_fixture(tmp_path / f"repo-{index}")
        if target == "registry":
            payload = json.loads(registry_path.read_text(encoding="utf-8"))
            payload["entries"][0][field] = value
            registry_path.write_text(json.dumps(payload), encoding="utf-8")
        else:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            section = "scope" if target == "report_scope" else "result"
            report[section][field] = value
            report_path.write_text(json.dumps(report), encoding="utf-8")
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            registry["entries"][0]["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
            registry_path.write_text(json.dumps(registry), encoding="utf-8")

        assert load_codex_acceptance_registry(registry_path).entries == ()


def test_codex_registry_rejects_artifact_escape_symlink_and_duplicates(tmp_path: Path) -> None:
    registry_path, report_path = _write_fixture(tmp_path / "repo")
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["entries"][0]["evidence_artifact"] = "../outside.json"
    registry_path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_codex_acceptance_registry(registry_path).entries == ()

    registry_path, report_path = _write_fixture(tmp_path / "repo-symlink")
    real_report = report_path.with_name("real-report.json")
    report_path.replace(real_report)
    report_path.symlink_to(real_report)
    assert load_codex_acceptance_registry(registry_path).entries == ()

    registry_path, _report_path = _write_fixture(tmp_path / "repo-duplicate")
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["entries"].append(dict(payload["entries"][0]))
    registry_path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_codex_acceptance_registry(registry_path).entries == ()

    registry_path, _report_path = _write_fixture(tmp_path / "repo-registry-symlink")
    real_registry = registry_path.with_name("real-registry.json")
    registry_path.replace(real_registry)
    registry_path.symlink_to(real_registry)
    assert load_codex_acceptance_registry(registry_path).entries == ()
