from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
SUMMARY_PATH = REPO_ROOT / "infra" / "scripts" / "test_report_summary.py"
LOAD_PATH = REPO_ROOT / "infra" / "scripts" / "load_gateway_request_path.py"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


summary = _load_module("hawk_test_report_summary", SUMMARY_PATH)
load = _load_module("hawk_load_gateway_request_path", LOAD_PATH)


def _iso(offset_ms: float) -> str:
    base = datetime(2026, 7, 24, 8, 0, tzinfo=timezone.utc)
    return (base + timedelta(milliseconds=offset_ms)).isoformat().replace("+00:00", "Z")


def _metadata(
    *,
    warmup_pairs: int = 1,
    measured_pairs: int = 2,
    payload_hash: str = "a" * 64,
) -> dict[str, Any]:
    return {
        "schema_version": "hawk.gateway-benchmark-metadata/1.2",
        "run_id": "run-20260724-test",
        "environment": {
            "label": "test-fixture",
            "operating_system": "TestOS 1",
            "python_version": "3.12.0",
        },
        "hardware": {
            "machine": "test-machine",
            "processor": "test-processor",
            "logical_cpu_count": 4,
            "memory_bytes": 8_000_000_000,
        },
        "source": {
            "revision": "0123456789abcdef0123456789abcdef01234567",
            "dirty": True,
            "dirty_patch_sha256": "f" * 64,
            "approved_patch_sha256": "f" * 64,
            "performance_claim_eligible": True,
            "ineligibility_reason": None,
        },
        "target": {
            "topology": "loopback_endpoints",
            "hardware_scope": "runner_only",
            "source_scope": "benchmark_tools_only",
            "hawk_process_provenance": "not_verified_by_harness",
        },
        "implementation": {
            "contract_version": "hawk.gateway-overhead-benchmark/1.2",
            "methodology_version": "hawk.gateway-overhead-methodology/1.2",
            "harness_sha256": "1" * 64,
            "reporter_sha256": "2" * 64,
            "methodology_sha256": "3" * 64,
        },
        "run_integrity": {
            "source_snapshot_stable": True,
            "implementation_snapshot_stable": True,
        },
        "governance_expectations": {
            "decision": "allow",
            "control_mode": "inline_allowed",
            "evidence_outcome": "present",
            "receipt_outcome": "present",
        },
        "policy_profile": "benchmark-allow-v1",
        "policy_version_id": "policy-version-test-1",
        "flags": {
            "receipts_enabled": True,
            "cache_profile": "cold",
        },
        "payload": {
            "bytes": 256,
            "sha256": payload_hash,
        },
        "concurrency": 2,
        "request_settings": {
            "timeout_seconds": 10.0,
            "http_version": "HTTP/1.1",
            "connection_mode": "persistent-per-leg-pool",
        },
        "warmup_pairs": warmup_pairs,
        "measured_pairs": measured_pairs,
        "upstream_stub": {
            "contract": "hawk-deterministic-openai-stub/1.0",
            "loopback_only": True,
            "response_proof_sha256": "b" * 64,
        },
        "started_at": _iso(0),
        "finished_at": _iso(1000),
    }


def _sample(
    *,
    pair_index: int,
    leg: str,
    sequence_index: int,
    excluded_warmup: bool,
    e2e_ms: float,
    start_ms: int,
    status_code: int = 200,
    outcome: str = "success",
    payload_hash: str = "a" * 64,
    metadata_hash: str = "e" * 64,
) -> dict[str, Any]:
    finished_ms = start_ms + e2e_ms
    is_hawk = leg == "hawk"
    return {
        "schema_version": "hawk.gateway-benchmark-sample/1.2",
        "run_id": "run-20260724-test",
        "pair_id": f"pair-{pair_index:06d}",
        "pair_index": pair_index,
        "leg": leg,
        "sequence_index": sequence_index,
        "excluded_warmup": excluded_warmup,
        "request_started_at": _iso(start_ms),
        "request_finished_at": _iso(finished_ms),
        "e2e_ms": e2e_ms,
        "request_bytes": 256,
        "request_payload_sha256": payload_hash,
        "metadata_sha256": metadata_hash,
        "response_bytes": 128,
        "response_sha256": "c" * 64,
        "upstream_proof_sha256": "b" * 64,
        "status_code": status_code,
        "outcome": outcome,
        "decision": "allow" if is_hawk and outcome == "success" else ("direct" if not is_hawk else "unknown"),
        "control_mode": (
            "inline_allowed"
            if is_hawk and outcome == "success"
            else ("direct" if not is_hawk else "unknown")
        ),
        "evidence_outcome": (
            "present"
            if is_hawk and outcome == "success"
            else ("not_applicable" if not is_hawk else "unknown")
        ),
        "receipt_outcome": (
            "present"
            if is_hawk and outcome == "success"
            else ("not_applicable" if not is_hawk else "unknown")
        ),
        "failure_class": "none" if outcome == "success" else "http_error",
    }


def _valid_samples(metadata: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    # Warmup pair 0 uses baseline→Hawk. Measured pair 1 alternates Hawk→baseline.
    # Pair 2 alternates back to baseline→Hawk.
    bound_metadata = metadata or _metadata()
    metadata_hash = hashlib.sha256(
        summary.canonical_json_bytes(bound_metadata)
    ).hexdigest()
    samples = [
        _sample(pair_index=0, leg="baseline", sequence_index=0, excluded_warmup=True, e2e_ms=10.0, start_ms=0),
        _sample(pair_index=0, leg="hawk", sequence_index=1, excluded_warmup=True, e2e_ms=20.0, start_ms=10),
        _sample(pair_index=1, leg="hawk", sequence_index=2, excluded_warmup=False, e2e_ms=8.0, start_ms=100),
        _sample(pair_index=1, leg="baseline", sequence_index=3, excluded_warmup=False, e2e_ms=10.0, start_ms=108),
        _sample(
            pair_index=2,
            leg="baseline",
            sequence_index=4,
            excluded_warmup=False,
            e2e_ms=20.0,
            start_ms=200,
            status_code=500,
            outcome="failure",
        ),
        _sample(pair_index=2, leg="hawk", sequence_index=5, excluded_warmup=False, e2e_ms=25.0, start_ms=220),
    ]
    for sample in samples:
        sample["metadata_sha256"] = metadata_hash
    return samples


def _raw_bytes(samples: list[dict[str, Any]]) -> bytes:
    return b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        for item in samples
    )


def _write_run(run_dir: Path, metadata: dict[str, Any], samples: list[dict[str, Any]]) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (run_dir / "samples.ndjson").write_bytes(_raw_bytes(samples))


def test_paired_leg_order_is_interleaved_and_alternates_first_leg() -> None:
    assert load.paired_leg_order(0) == ("baseline", "hawk")
    assert load.paired_leg_order(1) == ("hawk", "baseline")
    assert load.paired_leg_order(2) == ("baseline", "hawk")


def test_hawk_target_and_upstream_must_be_loopback_without_claiming_hawk_provenance() -> None:
    assert (
        load._validate_url(
            "http://127.0.0.1:8000",
            label="Hawk base URL",
            require_loopback=True,
        )
        == "http://127.0.0.1:8000"
    )
    with pytest.raises(ValueError, match="loopback"):
        load._validate_url(
            "http://192.0.2.50:8000",
            label="Hawk base URL",
            require_loopback=True,
        )
    source = inspect.getsource(load.run_benchmark)
    assert "label=\"Hawk base URL\"" in source
    assert "require_loopback=True" in source
    metadata = _metadata()
    assert metadata["target"] == {
        "topology": "loopback_endpoints",
        "hardware_scope": "runner_only",
        "source_scope": "benchmark_tools_only",
        "hawk_process_provenance": "not_verified_by_harness",
    }


def test_deterministic_http_clients_disable_environment_proxy_inheritance() -> None:
    options = load.deterministic_client_options(
        timeout=object(),
        limits=object(),
    )
    assert options["trust_env"] is False
    assert options["http2"] is False
    source = inspect.getsource(load.run_benchmark) + inspect.getsource(load._verify_stub)
    assert "deterministic_client_options" in source


def test_metadata_binds_exact_harness_reporter_and_methodology_bytes() -> None:
    binding = load.implementation_binding(REPO_ROOT)

    assert binding["contract_version"] == "hawk.gateway-overhead-benchmark/1.2"
    assert binding["methodology_version"] == "hawk.gateway-overhead-methodology/1.2"
    assert binding["harness_sha256"] == hashlib.sha256(LOAD_PATH.read_bytes()).hexdigest()
    assert binding["reporter_sha256"] == hashlib.sha256(SUMMARY_PATH.read_bytes()).hexdigest()
    methodology = REPO_ROOT / "docs" / "benchmarks" / "methodology.md"
    assert binding["methodology_sha256"] == hashlib.sha256(methodology.read_bytes()).hexdigest()


def test_source_claim_binding_compares_approval_to_actual_dirty_patch() -> None:
    unapproved = load.build_source_claim(
        revision="a" * 40,
        dirty=True,
        dirty_patch_sha256="b" * 64,
        approved_patch_sha256=None,
    )
    approved = load.build_source_claim(
        revision="a" * 40,
        dirty=True,
        dirty_patch_sha256="b" * 64,
        approved_patch_sha256="b" * 64,
    )
    mismatched = load.build_source_claim(
        revision="a" * 40,
        dirty=True,
        dirty_patch_sha256="b" * 64,
        approved_patch_sha256="c" * 64,
    )
    clean = load.build_source_claim(
        revision="a" * 40,
        dirty=False,
        dirty_patch_sha256=None,
        approved_patch_sha256=None,
    )

    assert unapproved["performance_claim_eligible"] is False
    assert unapproved["ineligibility_reason"] == "dirty_tree_without_approved_patch_hash"
    assert approved["performance_claim_eligible"] is True
    assert approved["ineligibility_reason"] is None
    assert mismatched["performance_claim_eligible"] is False
    assert mismatched["ineligibility_reason"] == "dirty_tree_patch_hash_mismatch"
    assert clean["performance_claim_eligible"] is True


def test_source_snapshot_hash_changes_with_actual_untracked_content(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "benchmark@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Benchmark Test"],
        cwd=tmp_path,
        check=True,
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)

    untracked = tmp_path / "untracked.txt"
    untracked.write_text("first\n", encoding="utf-8")
    first = load.source_snapshot(tmp_path)
    untracked.write_text("second\n", encoding="utf-8")
    second = load.source_snapshot(tmp_path)

    assert first["dirty"] is True
    assert first["dirty_patch_sha256"] != second["dirty_patch_sha256"]


def test_source_snapshot_scopes_status_and_content_to_requested_subtree(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "benchmark@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Benchmark Test"],
        cwd=tmp_path,
        check=True,
    )
    tools_root = tmp_path / "tools"
    tools_root.mkdir()
    (tools_root / "harness.py").write_text("stable\n", encoding="utf-8")
    sibling = tmp_path / "outside.txt"
    sibling.write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)

    sibling.write_text("outside change one\n", encoding="utf-8")
    first = load.source_snapshot(tools_root)
    sibling.write_text("outside change two\n", encoding="utf-8")
    second = load.source_snapshot(tools_root)

    assert first == second == {
        "revision": first["revision"],
        "dirty": False,
        "dirty_patch_sha256": None,
    }


def test_run_integrity_requires_identical_pre_and_post_snapshots() -> None:
    source = {"revision": "a" * 40, "dirty": False, "dirty_patch_sha256": None}
    implementation = {
        "contract_version": "hawk.gateway-overhead-benchmark/1.2",
        "methodology_version": "hawk.gateway-overhead-methodology/1.2",
        "harness_sha256": "1" * 64,
        "reporter_sha256": "2" * 64,
        "methodology_sha256": "3" * 64,
    }

    assert load.build_run_integrity(
        source_before=source,
        source_after=source,
        implementation_before=implementation,
        implementation_after=implementation,
    ) == {
        "source_snapshot_stable": True,
        "implementation_snapshot_stable": True,
    }
    assert load.build_run_integrity(
        source_before=source,
        source_after={**source, "revision": "b" * 40},
        implementation_before=implementation,
        implementation_after={**implementation, "harness_sha256": "4" * 64},
    ) == {
        "source_snapshot_stable": False,
        "implementation_snapshot_stable": False,
    }


def test_stub_attestation_is_fresh_per_stub_session_and_run_request_nonce() -> None:
    first = load.expected_upstream_proof(
        stub_session_nonce="a" * 64,
        request_nonce="b" * 64,
    )
    assert first != load.expected_upstream_proof(
        stub_session_nonce="c" * 64,
        request_nonce="b" * 64,
    )
    assert first != load.expected_upstream_proof(
        stub_session_nonce="a" * 64,
        request_nonce="d" * 64,
    )
    assert load.stub_server_class("::1").address_family == socket.AF_INET6
    assert load.stub_server_class("127.0.0.1").address_family == socket.AF_INET


def test_summary_uses_only_measured_pairs_and_preserves_negative_overhead() -> None:
    metadata = _metadata()
    samples = _valid_samples()
    raw = _raw_bytes(samples)

    result = summary.build_benchmark_summary(metadata=metadata, samples=samples, raw_samples=raw)

    assert result["raw_samples_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["sample_counts"] == {
        "total": 6,
        "excluded_warmup": 2,
        "measured": 4,
        "measured_pairs": 2,
    }
    assert result["comparison"] == {
        "eligible_pairs": 1,
        "excluded_pairs": 1,
        "excluded_pair_reasons": {"baseline:http_error": 1},
        "latency_ms": {
            "baseline": {"p50": 10.0, "p95": 10.0, "p99": 10.0},
            "hawk": {"p50": 8.0, "p95": 8.0, "p99": 8.0},
        },
        "observed_paired_overhead_ms": {
            "p50": -2.0,
            "p95": -2.0,
            "p99": -2.0,
        },
    }
    assert result["diagnostic_attempt_latency_ms"] == {
        "all_measured": {
            "baseline": {"p50": 10.0, "p95": 20.0, "p99": 20.0},
            "hawk": {"p50": 8.0, "p95": 25.0, "p99": 25.0},
        },
        "failed_attempts": {
            "baseline": {"p50": 20.0, "p95": 20.0, "p99": 20.0},
            "hawk": None,
        },
    }
    assert result["performance_claim"] == {
        "eligible": False,
        "reasons": [
            "insufficient_eligible_pairs",
            "excluded_comparison_pairs",
        ],
    }
    assert result["failure_rate"] == {
        "all_measured": 0.25,
        "baseline": 0.5,
        "hawk": 0.0,
    }
    assert result["throughput_rps"]["measured_requests"] == pytest.approx(4 / 0.145)


def test_no_publishable_overhead_when_no_pair_has_two_successful_reconciled_legs() -> None:
    metadata = _metadata()
    samples = _valid_samples(metadata)
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    for sample in samples:
        if not sample["excluded_warmup"] and sample["leg"] == "hawk":
            sample.update(
                {
                    "status_code": 0,
                    "outcome": "failure",
                    "failure_class": "timeout",
                    "response_bytes": 0,
                    "response_sha256": empty_sha256,
                    "upstream_proof_sha256": empty_sha256,
                    "decision": "unknown",
                    "control_mode": "unknown",
                    "evidence_outcome": "unknown",
                    "receipt_outcome": "unknown",
                }
            )

    result = summary.build_benchmark_summary(
        metadata=metadata,
        samples=samples,
        raw_samples=_raw_bytes(samples),
    )

    assert result["comparison"]["eligible_pairs"] == 0
    assert result["comparison"]["excluded_pairs"] == 2
    assert result["comparison"]["latency_ms"] == {"baseline": None, "hawk": None}
    assert result["comparison"]["observed_paired_overhead_ms"] is None
    assert result["performance_claim"] == {
        "eligible": False,
        "reasons": [
            "no_valid_comparison_pairs",
            "excluded_comparison_pairs",
        ],
    }
    assert result["diagnostic_attempt_latency_ms"]["failed_attempts"]["hawk"] is not None


def test_dirty_source_without_approved_patch_is_claim_ineligible() -> None:
    metadata = _metadata()
    metadata["source"].update(
        {
            "dirty_patch_sha256": "f" * 64,
            "approved_patch_sha256": None,
            "performance_claim_eligible": False,
            "ineligibility_reason": "dirty_tree_without_approved_patch_hash",
        }
    )
    samples = _valid_samples(metadata)

    result = summary.build_benchmark_summary(
        metadata=metadata,
        samples=samples,
        raw_samples=_raw_bytes(samples),
    )

    assert result["performance_claim"] == {
        "eligible": False,
        "reasons": [
            "insufficient_eligible_pairs",
            "excluded_comparison_pairs",
            "dirty_tree_without_approved_patch_hash",
        ],
    }


def test_performance_claim_requires_100_complete_governed_pairs() -> None:
    metadata = _metadata()
    assert summary.performance_claim_reasons(
        eligible_pairs=100,
        measured_pairs=100,
        excluded_pairs=0,
        metadata=metadata,
    ) == []
    assert summary.performance_claim_reasons(
        eligible_pairs=99,
        measured_pairs=100,
        excluded_pairs=1,
        metadata=metadata,
    ) == [
        "insufficient_eligible_pairs",
        "excluded_comparison_pairs",
    ]


def test_unknown_hawk_governance_assertions_are_excluded_from_headline() -> None:
    metadata = _metadata()
    samples = _valid_samples(metadata)
    hawk = next(
        sample
        for sample in samples
        if sample["pair_index"] == 1 and sample["leg"] == "hawk"
    )
    hawk.update(
        {
            "decision": "unknown",
            "control_mode": "unknown",
            "evidence_outcome": "unknown",
            "receipt_outcome": "unknown",
        }
    )

    result = summary.build_benchmark_summary(
        metadata=metadata,
        samples=samples,
        raw_samples=_raw_bytes(samples),
    )

    assert result["comparison"]["eligible_pairs"] == 0
    assert result["comparison"]["excluded_pair_reasons"] == {
        "baseline:http_error": 1,
        "hawk:control_mode_not_expected": 1,
        "hawk:decision_not_expected": 1,
        "hawk:evidence_outcome_not_expected": 1,
        "hawk:receipt_outcome_not_expected": 1,
    }


def test_unstable_run_snapshots_are_claim_ineligible() -> None:
    metadata = _metadata()
    metadata["run_integrity"]["source_snapshot_stable"] = False
    samples = _valid_samples(metadata)

    result = summary.build_benchmark_summary(
        metadata=metadata,
        samples=samples,
        raw_samples=_raw_bytes(samples),
    )

    assert "source_changed_during_run" in result["performance_claim"]["reasons"]


def test_summary_is_byte_deterministic_for_identical_raw_samples() -> None:
    metadata = _metadata()
    samples = _valid_samples()
    raw = _raw_bytes(samples)

    first = summary.build_benchmark_summary(metadata=metadata, samples=samples, raw_samples=raw)
    second = summary.build_benchmark_summary(metadata=metadata, samples=samples, raw_samples=raw)

    assert summary.canonical_json_bytes(first) == summary.canonical_json_bytes(second)


def test_summary_metrics_do_not_depend_on_descriptive_metadata_or_warmup_values() -> None:
    first_metadata = _metadata()
    samples = _valid_samples(first_metadata)
    raw = _raw_bytes(samples)
    second_metadata = _metadata()
    second_metadata["environment"]["label"] = "different-valid-environment"
    second_metadata["hardware"]["logical_cpu_count"] = 128
    second_metadata["source"]["dirty"] = False
    second_metadata["source"]["dirty_patch_sha256"] = None
    second_metadata["source"]["approved_patch_sha256"] = None
    second_metadata["started_at"] = _iso(-50)
    second_samples = _valid_samples(second_metadata)
    second_samples[0]["e2e_ms"] = 1.0
    second_samples[0]["request_finished_at"] = _iso(1)
    second_samples[1]["e2e_ms"] = 2.0
    second_samples[1]["request_finished_at"] = _iso(12)
    second_raw = _raw_bytes(second_samples)

    first = summary.build_benchmark_summary(
        metadata=first_metadata,
        samples=samples,
        raw_samples=raw,
    )
    second = summary.build_benchmark_summary(
        metadata=second_metadata,
        samples=second_samples,
        raw_samples=second_raw,
    )

    ignored_keys = {"raw_samples_sha256"}
    assert {key: value for key, value in first.items() if key not in ignored_keys} == {
        key: value for key, value in second.items() if key not in ignored_keys
    }


def test_artifact_verification_detects_sample_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, _metadata(), _valid_samples())
    summary.write_benchmark_summary(run_dir)

    with (run_dir / "samples.ndjson").open("ab") as handle:
        handle.write(b" \n")

    with pytest.raises(summary.ArtifactValidationError, match="checksum"):
        summary.verify_benchmark_artifacts(run_dir)


def test_artifact_verification_detects_summary_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, _metadata(), _valid_samples())
    written = summary.write_benchmark_summary(run_dir)
    written["comparison"]["observed_paired_overhead_ms"]["p99"] = 0.0
    (run_dir / "summary.json").write_bytes(summary.canonical_json_bytes(written) + b"\n")

    with pytest.raises(summary.ArtifactValidationError, match="validated raw samples"):
        summary.verify_benchmark_artifacts(run_dir)


def test_artifact_verification_detects_metadata_tampering(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    metadata = _metadata()
    samples = _valid_samples()
    _write_run(run_dir, metadata, samples)
    summary.write_benchmark_summary(run_dir)
    metadata["source"]["revision"] = "f" * 40
    (run_dir / "metadata.json").write_bytes(
        summary.canonical_json_bytes(metadata) + b"\n"
    )

    with pytest.raises(summary.ArtifactValidationError, match="metadata binding"):
        summary.verify_benchmark_artifacts(run_dir)


def test_artifact_verification_rejects_noncanonical_metadata(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    metadata = _metadata()
    _write_run(run_dir, metadata, _valid_samples(metadata))
    summary.write_benchmark_summary(run_dir)
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(summary.ArtifactValidationError, match="metadata.json is not canonical"):
        summary.verify_benchmark_artifacts(run_dir)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda metadata, samples: samples.pop(), "sample count"),
        (
            lambda metadata, samples: samples[3].__setitem__("request_payload_sha256", "d" * 64),
            "payload",
        ),
        (
            lambda metadata, samples: samples[2].__setitem__("excluded_warmup", True),
            "warmup",
        ),
        (
            lambda metadata, samples: samples[0].__setitem__("prompt", "raw customer secret"),
            "unknown sample fields",
        ),
    ],
)
def test_incomplete_mismatched_or_raw_artifacts_are_rejected(
    mutator: Any,
    message: str,
) -> None:
    metadata = _metadata()
    samples = _valid_samples()
    mutator(metadata, samples)

    with pytest.raises(summary.ArtifactValidationError, match=message):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=samples)


def test_sensitive_flag_names_and_values_are_rejected() -> None:
    metadata = _metadata()
    metadata["flags"] = {"api_key": "sk-test-secret"}

    with pytest.raises(summary.ArtifactValidationError, match="sensitive"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=_valid_samples())


@pytest.mark.parametrize(
    ("field_path", "secret_value"),
    [
        (("environment", "label"), "Bearer top-secret"),
        (("policy_profile",), "sk-test-secret"),
    ],
)
def test_sensitive_descriptive_metadata_is_rejected(
    field_path: tuple[str, ...],
    secret_value: str,
) -> None:
    metadata = _metadata()
    target: dict[str, Any] = metadata
    for key in field_path[:-1]:
        target = target[key]
    target[field_path[-1]] = secret_value

    with pytest.raises(summary.ArtifactValidationError, match="sensitive"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=_valid_samples())


def test_sensitive_run_ids_are_rejected() -> None:
    metadata = _metadata()
    metadata["run_id"] = "Bearer top-secret"
    samples = _valid_samples(metadata)

    with pytest.raises(summary.ArtifactValidationError, match="sensitive"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=samples)


def test_hawk_leg_cannot_claim_direct_or_not_applicable_semantics() -> None:
    metadata = _metadata()
    samples = _valid_samples(metadata)
    hawk_sample = next(sample for sample in samples if sample["leg"] == "hawk")
    hawk_sample.update(
        {
            "decision": "direct",
            "control_mode": "direct",
            "evidence_outcome": "not_applicable",
            "receipt_outcome": "not_applicable",
        }
    )

    with pytest.raises(summary.ArtifactValidationError, match="Hawk sample"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=samples)


@pytest.mark.parametrize(
    "changes",
    [
        {"status_code": 200, "outcome": "failure", "failure_class": "timeout"},
        {"status_code": 0, "outcome": "failure", "failure_class": "http_error"},
        {
            "status_code": 0,
            "outcome": "failure",
            "failure_class": "transport_error",
            "response_bytes": 1,
        },
        {"status_code": 500, "outcome": "failure", "failure_class": "invalid_response"},
        {"status_code": 200, "outcome": "failure", "failure_class": "invalid_response"},
        {
            "status_code": 200,
            "outcome": "failure",
            "failure_class": "upstream_proof_mismatch",
        },
    ],
)
def test_impossible_failure_class_and_status_combinations_are_rejected(
    changes: dict[str, Any],
) -> None:
    metadata = _metadata()
    samples = _valid_samples(metadata)
    samples[4].update(changes)

    with pytest.raises(summary.ArtifactValidationError, match="failure_class"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=samples)


def test_recorded_concurrency_cannot_understate_overlapping_pairs() -> None:
    metadata = _metadata()
    metadata["concurrency"] = 1
    samples = _valid_samples(metadata)
    samples[4].update(
        {
            "request_started_at": _iso(110),
            "request_finished_at": _iso(130),
        }
    )
    samples[5].update(
        {
            "request_started_at": _iso(130),
            "request_finished_at": _iso(155),
        }
    )

    with pytest.raises(summary.ArtifactValidationError, match="concurrency"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=samples)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda metadata, samples: samples[2].__setitem__("e2e_ms", 999999.0),
            "e2e_ms",
        ),
        (
            lambda metadata, samples: samples[3].update(
                {
                    "request_started_at": _iso(90),
                    "request_finished_at": _iso(100),
                }
            ),
            "chronology",
        ),
        (
            lambda metadata, samples: samples[1].update(
                {
                    "request_started_at": _iso(95),
                    "request_finished_at": _iso(115),
                }
            ),
            "warmup",
        ),
        (
            lambda metadata, samples: metadata.__setitem__("started_at", _iso(5)),
            "run bounds",
        ),
    ],
)
def test_temporally_inconsistent_artifacts_are_rejected(
    mutator: Any,
    message: str,
) -> None:
    metadata = _metadata()
    samples = _valid_samples(metadata)
    mutator(metadata, samples)
    metadata_hash = hashlib.sha256(summary.canonical_json_bytes(metadata)).hexdigest()
    for sample in samples:
        sample["metadata_sha256"] = metadata_hash

    with pytest.raises(summary.ArtifactValidationError, match=message):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=samples)


def test_unavailable_hardware_counts_are_explicit_unknown_not_guessed() -> None:
    metadata = _metadata()
    metadata["hardware"]["logical_cpu_count"] = None
    metadata["hardware"]["memory_bytes"] = None

    validated, _ = summary.validate_benchmark_artifacts(
        metadata=metadata,
        samples=_valid_samples(metadata),
    )

    assert validated["hardware"]["logical_cpu_count"] is None
    assert validated["hardware"]["memory_bytes"] is None


def test_metadata_and_samples_reject_missing_required_fields() -> None:
    metadata = _metadata()
    del metadata["source"]["dirty"]
    with pytest.raises(summary.ArtifactValidationError, match="source"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=_valid_samples())

    samples = _valid_samples()
    del samples[0]["receipt_outcome"]
    with pytest.raises(summary.ArtifactValidationError, match="sample fields"):
        summary.validate_benchmark_artifacts(metadata=_metadata(), samples=samples)

    metadata = _metadata()
    del metadata["policy_version_id"]
    with pytest.raises(summary.ArtifactValidationError, match="policy_version_id"):
        summary.validate_benchmark_artifacts(metadata=metadata, samples=_valid_samples())


def test_sample_builder_never_persists_raw_payload_headers_or_response() -> None:
    record = load.build_sample_record(
        run_id="run-20260724-test",
        pair_index=1,
        leg="hawk",
        sequence_index=2,
        excluded_warmup=False,
        request_started_at=_iso(0),
        request_finished_at=_iso(8),
        e2e_ms=8.25,
        request_body=b'{"prompt":"customer secret","api_key":"sk-test"}',
        response_body=b'{"completion":"private answer"}',
        status_code=200,
        parsed_response={
            "hawk": {
                "final_decision": "allow",
                "control_mode": "inline_allowed",
                "evidence_node_ids": ["evidence-1"],
                "gateway_trace": {"secure_gateway": {"decision_receipt_id": "receipt-1"}},
            }
        },
        upstream_proof="hawk-benchmark-upstream-v1",
        failure_class="none",
    )

    encoded = json.dumps(record, sort_keys=True)
    assert "customer secret" not in encoded
    assert "private answer" not in encoded
    assert "sk-test" not in encoded
    assert set(record) == summary.SAMPLE_FIELDS
    assert record["evidence_outcome"] == "present"
    assert record["receipt_outcome"] == "present"


def test_unknown_decision_and_control_values_are_conservative() -> None:
    record = load.build_sample_record(
        run_id="run-20260724-test",
        pair_index=1,
        leg="hawk",
        sequence_index=2,
        excluded_warmup=False,
        request_started_at=_iso(0),
        request_finished_at=_iso(8),
        e2e_ms=8.25,
        request_body=b"{}",
        response_body=b"{}",
        status_code=200,
        parsed_response={"hawk": {"final_decision": "magic_allow", "control_mode": "super_inline"}},
        upstream_proof="hawk-benchmark-upstream-v1",
        failure_class="none",
    )

    assert record["decision"] == "unknown"
    assert record["control_mode"] == "unknown"
    assert record["evidence_outcome"] == "unknown"
    assert record["receipt_outcome"] == "unknown"


def test_malformed_evidence_and_receipt_values_never_count_as_present() -> None:
    record = load.build_sample_record(
        run_id="run-20260724-test",
        pair_index=1,
        leg="hawk",
        sequence_index=2,
        excluded_warmup=False,
        request_started_at=_iso(0),
        request_finished_at=_iso(8),
        e2e_ms=8.25,
        request_body=b"{}",
        response_body=b"{}",
        status_code=200,
        parsed_response={
            "hawk": {
                "final_decision": "allow",
                "control_mode": "inline_allowed",
                "evidence_node_ids": True,
                "evidence_bundle": {"unexpected": True},
                "decision_receipt_id": True,
                "execution_receipt_id": {"id": "not-a-string-field"},
            }
        },
        upstream_proof="run-unique-proof",
        failure_class="none",
    )

    assert record["evidence_outcome"] == "missing"
    assert record["receipt_outcome"] == "missing"
