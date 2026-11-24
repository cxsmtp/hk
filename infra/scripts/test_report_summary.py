from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


METADATA_SCHEMA_VERSION = "hawk.gateway-benchmark-metadata/1.2"
SAMPLE_SCHEMA_VERSION = "hawk.gateway-benchmark-sample/1.2"
SUMMARY_SCHEMA_VERSION = "hawk.gateway-benchmark-summary/1.2"
MIN_PUBLISHABLE_MEASURED_PAIRS = 100

METADATA_FIELDS = {
    "schema_version",
    "run_id",
    "environment",
    "hardware",
    "source",
    "target",
    "implementation",
    "run_integrity",
    "governance_expectations",
    "policy_profile",
    "policy_version_id",
    "flags",
    "payload",
    "concurrency",
    "request_settings",
    "warmup_pairs",
    "measured_pairs",
    "upstream_stub",
    "started_at",
    "finished_at",
}
SAMPLE_FIELDS = {
    "schema_version",
    "run_id",
    "pair_id",
    "pair_index",
    "leg",
    "sequence_index",
    "excluded_warmup",
    "request_started_at",
    "request_finished_at",
    "e2e_ms",
    "request_bytes",
    "request_payload_sha256",
    "metadata_sha256",
    "response_bytes",
    "response_sha256",
    "upstream_proof_sha256",
    "status_code",
    "outcome",
    "decision",
    "control_mode",
    "evidence_outcome",
    "receipt_outcome",
    "failure_class",
}

_ENVIRONMENT_FIELDS = {"label", "operating_system", "python_version"}
_HARDWARE_FIELDS = {
    "machine",
    "processor",
    "logical_cpu_count",
    "memory_bytes",
}
_SOURCE_FIELDS = {
    "revision",
    "dirty",
    "dirty_patch_sha256",
    "approved_patch_sha256",
    "performance_claim_eligible",
    "ineligibility_reason",
}
_TARGET_FIELDS = {
    "topology",
    "hardware_scope",
    "source_scope",
    "hawk_process_provenance",
}
_IMPLEMENTATION_FIELDS = {
    "contract_version",
    "methodology_version",
    "harness_sha256",
    "reporter_sha256",
    "methodology_sha256",
}
_RUN_INTEGRITY_FIELDS = {
    "source_snapshot_stable",
    "implementation_snapshot_stable",
}
_GOVERNANCE_EXPECTATION_FIELDS = {
    "decision",
    "control_mode",
    "evidence_outcome",
    "receipt_outcome",
}
_PAYLOAD_FIELDS = {"bytes", "sha256"}
_REQUEST_SETTINGS_FIELDS = {
    "timeout_seconds",
    "http_version",
    "connection_mode",
}
_UPSTREAM_FIELDS = {"contract", "loopback_only", "response_proof_sha256"}
_SAFE_FLAG_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40,64}$")
_SENSITIVE_KEY_PARTS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}
_SENSITIVE_VALUE_MARKERS = (
    "-----begin private key-----",
    "bearer ",
)
_DECISIONS = {
    "direct",
    "allow",
    "warn",
    "redact",
    "hold_for_approval",
    "block",
    "unknown",
}
_CONTROL_MODES = {
    "direct",
    "inline_allowed",
    "inline_prevented",
    "monitor_only",
    "post_execution",
    "shadow",
    "unknown",
}
_OUTCOMES = {"success", "failure"}
_PROOF_OUTCOMES = {"present", "missing", "not_applicable", "unknown"}
_FAILURE_CLASSES = {
    "none",
    "http_error",
    "timeout",
    "transport_error",
    "invalid_response",
    "upstream_proof_mismatch",
}


class ArtifactValidationError(ValueError):
    """Raised when a benchmark artifact is incomplete, unsafe, or inconsistent."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _require_exact_fields(
    value: Any,
    *,
    fields: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactValidationError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        detail = []
        if missing:
            detail.append(f"missing={missing}")
        if unknown:
            detail.append(f"unknown={unknown}")
        raise ArtifactValidationError(f"{label} fields are invalid: {', '.join(detail)}")
    return value


def _require_nonempty_string(value: Any, *, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ArtifactValidationError(f"{label} must be a non-empty bounded string")
    return value


def _require_safe_descriptive_string(
    value: Any,
    *,
    label: str,
    maximum: int = 256,
) -> str:
    result = _require_nonempty_string(value, label=label, maximum=maximum)
    if _contains_sensitive_value(result):
        raise ArtifactValidationError(f"{label} contains sensitive material")
    return result


def _contains_sensitive_value(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _SENSITIVE_VALUE_MARKERS) or bool(
        re.search(r"(^|[^a-z0-9])sk-[a-z0-9]", lowered)
    )


def _require_nonnegative_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArtifactValidationError(f"{label} must be a non-negative integer")
    return value


def _require_positive_int(value: Any, *, label: str) -> int:
    result = _require_nonnegative_int(value, label=label)
    if result == 0:
        raise ArtifactValidationError(f"{label} must be positive")
    return result


def _require_finite_number(value: Any, *, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArtifactValidationError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise ArtifactValidationError(f"{label} must be finite and at least {minimum}")
    return result


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    text = _require_nonempty_string(value, label=label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArtifactValidationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ArtifactValidationError(f"{label} must include a timezone")
    return parsed


def _require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _HEX_SHA256.fullmatch(value) is None:
        raise ArtifactValidationError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _validate_flags(value: Any) -> None:
    if not isinstance(value, dict) or len(value) > 64:
        raise ArtifactValidationError("flags must be a bounded object")
    for key, flag_value in value.items():
        if not isinstance(key, str) or _SAFE_FLAG_KEY.fullmatch(key) is None:
            raise ArtifactValidationError("flag names must use safe snake_case")
        normalized_key = key.lower()
        if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
            raise ArtifactValidationError("sensitive flag names are forbidden")
        if isinstance(flag_value, bool):
            continue
        if isinstance(flag_value, int) and not isinstance(flag_value, bool):
            continue
        if isinstance(flag_value, float) and math.isfinite(flag_value):
            continue
        if isinstance(flag_value, str) and len(flag_value) <= 128:
            if _contains_sensitive_value(flag_value):
                raise ArtifactValidationError("sensitive flag values are forbidden")
            continue
        raise ArtifactValidationError("flag values must be bounded JSON scalars")


def validate_metadata(metadata: Any) -> dict[str, Any]:
    value = _require_exact_fields(metadata, fields=METADATA_FIELDS, label="metadata")
    if value["schema_version"] != METADATA_SCHEMA_VERSION:
        raise ArtifactValidationError("metadata schema_version is unsupported")
    _require_safe_descriptive_string(value["run_id"], label="run_id", maximum=128)

    environment = _require_exact_fields(
        value["environment"],
        fields=_ENVIRONMENT_FIELDS,
        label="environment",
    )
    for key in sorted(_ENVIRONMENT_FIELDS):
        _require_safe_descriptive_string(environment[key], label=f"environment.{key}")

    hardware = _require_exact_fields(
        value["hardware"],
        fields=_HARDWARE_FIELDS,
        label="hardware",
    )
    _require_safe_descriptive_string(hardware["machine"], label="hardware.machine")
    _require_safe_descriptive_string(hardware["processor"], label="hardware.processor")
    if hardware["logical_cpu_count"] is not None:
        _require_positive_int(
            hardware["logical_cpu_count"],
            label="hardware.logical_cpu_count",
        )
    if hardware["memory_bytes"] is not None:
        _require_positive_int(hardware["memory_bytes"], label="hardware.memory_bytes")

    source = _require_exact_fields(value["source"], fields=_SOURCE_FIELDS, label="source")
    if not isinstance(source["revision"], str) or _SOURCE_REVISION.fullmatch(source["revision"]) is None:
        raise ArtifactValidationError("source.revision must be a Git object identifier")
    if not isinstance(source["dirty"], bool):
        raise ArtifactValidationError("source.dirty must be boolean")
    dirty_patch_sha256 = source["dirty_patch_sha256"]
    if dirty_patch_sha256 is not None:
        _require_sha256(
            dirty_patch_sha256,
            label="source.dirty_patch_sha256",
        )
    approved_patch_sha256 = source["approved_patch_sha256"]
    if approved_patch_sha256 is not None:
        _require_sha256(
            approved_patch_sha256,
            label="source.approved_patch_sha256",
        )
    if not isinstance(source["performance_claim_eligible"], bool):
        raise ArtifactValidationError("source.performance_claim_eligible must be boolean")
    ineligibility_reason = source["ineligibility_reason"]
    if ineligibility_reason is not None:
        _require_safe_descriptive_string(
            ineligibility_reason,
            label="source.ineligibility_reason",
            maximum=128,
        )
    if source["dirty"]:
        if dirty_patch_sha256 is None:
            raise ArtifactValidationError(
                "dirty source must declare its calculated patch hash"
            )
        if approved_patch_sha256 is None:
            expected_source_eligible = False
            expected_source_reason = "dirty_tree_without_approved_patch_hash"
        elif approved_patch_sha256 != dirty_patch_sha256:
            expected_source_eligible = False
            expected_source_reason = "dirty_tree_patch_hash_mismatch"
        else:
            expected_source_eligible = True
            expected_source_reason = None
    else:
        expected_source_eligible = True
        expected_source_reason = None
    if source["performance_claim_eligible"] is not expected_source_eligible:
        raise ArtifactValidationError("source claim eligibility contradicts dirty-tree binding")
    if ineligibility_reason != expected_source_reason:
        raise ArtifactValidationError("source ineligibility reason contradicts dirty-tree binding")
    if not source["dirty"] and (
        dirty_patch_sha256 is not None or approved_patch_sha256 is not None
    ):
        raise ArtifactValidationError("clean source must not declare patch hashes")

    target = _require_exact_fields(
        value["target"],
        fields=_TARGET_FIELDS,
        label="target",
    )
    expected_target = {
        "topology": "loopback_endpoints",
        "hardware_scope": "runner_only",
        "source_scope": "benchmark_tools_only",
        "hawk_process_provenance": "not_verified_by_harness",
    }
    if target != expected_target:
        raise ArtifactValidationError(
            "target must use the closed, provenance-limited loopback contract"
        )

    implementation = _require_exact_fields(
        value["implementation"],
        fields=_IMPLEMENTATION_FIELDS,
        label="implementation",
    )
    if implementation["contract_version"] != "hawk.gateway-overhead-benchmark/1.2":
        raise ArtifactValidationError("implementation contract_version is unsupported")
    if implementation["methodology_version"] != "hawk.gateway-overhead-methodology/1.2":
        raise ArtifactValidationError("implementation methodology_version is unsupported")
    for field in ("harness_sha256", "reporter_sha256", "methodology_sha256"):
        _require_sha256(implementation[field], label=f"implementation.{field}")

    run_integrity = _require_exact_fields(
        value["run_integrity"],
        fields=_RUN_INTEGRITY_FIELDS,
        label="run_integrity",
    )
    for field in sorted(_RUN_INTEGRITY_FIELDS):
        if not isinstance(run_integrity[field], bool):
            raise ArtifactValidationError(f"run_integrity.{field} must be boolean")

    governance_expectations = _require_exact_fields(
        value["governance_expectations"],
        fields=_GOVERNANCE_EXPECTATION_FIELDS,
        label="governance_expectations",
    )
    expected_governance = {
        "decision": "allow",
        "control_mode": "inline_allowed",
        "evidence_outcome": "present",
        "receipt_outcome": "present",
    }
    if governance_expectations != expected_governance:
        raise ArtifactValidationError(
            "governance_expectations must use the closed governed-allow profile"
        )

    _require_safe_descriptive_string(
        value["policy_profile"],
        label="policy_profile",
        maximum=128,
    )
    _require_safe_descriptive_string(
        value["policy_version_id"],
        label="policy_version_id",
        maximum=256,
    )
    _validate_flags(value["flags"])

    payload = _require_exact_fields(value["payload"], fields=_PAYLOAD_FIELDS, label="payload")
    _require_positive_int(payload["bytes"], label="payload.bytes")
    _require_sha256(payload["sha256"], label="payload.sha256")

    concurrency = _require_positive_int(value["concurrency"], label="concurrency")
    if concurrency > 10_000:
        raise ArtifactValidationError("concurrency exceeds the bounded maximum")

    request_settings = _require_exact_fields(
        value["request_settings"],
        fields=_REQUEST_SETTINGS_FIELDS,
        label="request_settings",
    )
    _require_finite_number(
        request_settings["timeout_seconds"],
        label="request_settings.timeout_seconds",
        minimum=0.001,
    )
    _require_safe_descriptive_string(
        request_settings["http_version"],
        label="request_settings.http_version",
    )
    _require_safe_descriptive_string(
        request_settings["connection_mode"],
        label="request_settings.connection_mode",
    )

    _require_nonnegative_int(value["warmup_pairs"], label="warmup_pairs")
    _require_positive_int(value["measured_pairs"], label="measured_pairs")

    upstream = _require_exact_fields(
        value["upstream_stub"],
        fields=_UPSTREAM_FIELDS,
        label="upstream_stub",
    )
    if upstream["contract"] != "hawk-deterministic-openai-stub/1.0":
        raise ArtifactValidationError("upstream_stub.contract is unsupported")
    if upstream["loopback_only"] is not True:
        raise ArtifactValidationError("upstream_stub must be loopback-only")
    _require_sha256(
        upstream["response_proof_sha256"],
        label="upstream_stub.response_proof_sha256",
    )

    started = _parse_timestamp(value["started_at"], label="started_at")
    finished = _parse_timestamp(value["finished_at"], label="finished_at")
    if finished < started:
        raise ArtifactValidationError("finished_at precedes started_at")
    return value


def _validate_sample(sample: Any, *, index: int) -> dict[str, Any]:
    if isinstance(sample, dict):
        unknown_fields = sorted(set(sample) - SAMPLE_FIELDS)
        if unknown_fields:
            raise ArtifactValidationError(
                f"unknown sample fields at index {index}: {unknown_fields}"
            )
    value = _require_exact_fields(
        sample,
        fields=SAMPLE_FIELDS,
        label=f"sample fields at index {index}",
    )
    if value["schema_version"] != SAMPLE_SCHEMA_VERSION:
        raise ArtifactValidationError(f"sample schema_version at index {index} is unsupported")
    _require_safe_descriptive_string(
        value["run_id"],
        label=f"sample[{index}].run_id",
        maximum=128,
    )
    _require_safe_descriptive_string(
        value["pair_id"],
        label=f"sample[{index}].pair_id",
        maximum=128,
    )
    _require_nonnegative_int(value["pair_index"], label=f"sample[{index}].pair_index")
    if value["leg"] not in {"baseline", "hawk"}:
        raise ArtifactValidationError(f"sample[{index}].leg is invalid")
    _require_nonnegative_int(value["sequence_index"], label=f"sample[{index}].sequence_index")
    if not isinstance(value["excluded_warmup"], bool):
        raise ArtifactValidationError(f"sample[{index}].excluded_warmup must be boolean")
    started = _parse_timestamp(
        value["request_started_at"],
        label=f"sample[{index}].request_started_at",
    )
    finished = _parse_timestamp(
        value["request_finished_at"],
        label=f"sample[{index}].request_finished_at",
    )
    if finished < started:
        raise ArtifactValidationError(f"sample[{index}] finished before it started")
    e2e_ms = _require_finite_number(
        value["e2e_ms"],
        label=f"sample[{index}].e2e_ms",
    )
    timestamp_duration_ms = (finished - started).total_seconds() * 1000.0
    if abs(timestamp_duration_ms - e2e_ms) > 0.002:
        raise ArtifactValidationError(
            f"sample[{index}].e2e_ms contradicts its timestamp interval"
        )
    _require_positive_int(value["request_bytes"], label=f"sample[{index}].request_bytes")
    _require_sha256(
        value["request_payload_sha256"],
        label=f"sample[{index}].request_payload_sha256",
    )
    _require_sha256(
        value["metadata_sha256"],
        label=f"sample[{index}].metadata_sha256",
    )
    _require_nonnegative_int(value["response_bytes"], label=f"sample[{index}].response_bytes")
    _require_sha256(value["response_sha256"], label=f"sample[{index}].response_sha256")
    _require_sha256(
        value["upstream_proof_sha256"],
        label=f"sample[{index}].upstream_proof_sha256",
    )
    status_code = _require_nonnegative_int(
        value["status_code"],
        label=f"sample[{index}].status_code",
    )
    if status_code != 0 and not 100 <= status_code <= 599:
        raise ArtifactValidationError(f"sample[{index}].status_code is invalid")
    if value["outcome"] not in _OUTCOMES:
        raise ArtifactValidationError(f"sample[{index}].outcome is invalid")
    if value["decision"] not in _DECISIONS:
        raise ArtifactValidationError(f"sample[{index}].decision is invalid")
    if value["control_mode"] not in _CONTROL_MODES:
        raise ArtifactValidationError(f"sample[{index}].control_mode is invalid")
    if value["evidence_outcome"] not in _PROOF_OUTCOMES:
        raise ArtifactValidationError(f"sample[{index}].evidence_outcome is invalid")
    if value["receipt_outcome"] not in _PROOF_OUTCOMES:
        raise ArtifactValidationError(f"sample[{index}].receipt_outcome is invalid")
    if value["failure_class"] not in _FAILURE_CLASSES:
        raise ArtifactValidationError(f"sample[{index}].failure_class is invalid")
    if value["outcome"] == "success":
        if not 200 <= status_code < 300:
            raise ArtifactValidationError(f"sample[{index}] success has non-success status")
        if value["failure_class"] != "none":
            raise ArtifactValidationError(f"sample[{index}] success has a failure class")
    elif value["failure_class"] == "none":
        raise ArtifactValidationError(f"sample[{index}] failure lacks a failure class")
    else:
        failure_class = value["failure_class"]
        if status_code == 0:
            if failure_class not in {"timeout", "transport_error"}:
                raise ArtifactValidationError(
                    f"sample[{index}].failure_class contradicts status 0"
                )
            empty_sha256 = hashlib.sha256(b"").hexdigest()
            if (
                value["response_bytes"] != 0
                or value["response_sha256"] != empty_sha256
                or value["upstream_proof_sha256"] != empty_sha256
            ):
                raise ArtifactValidationError(
                    f"sample[{index}].failure_class requires an empty transport response"
                )
        elif not 200 <= status_code < 300:
            if failure_class != "http_error":
                raise ArtifactValidationError(
                    f"sample[{index}].failure_class must be http_error for non-2xx status"
                )
        elif failure_class not in {"invalid_response", "upstream_proof_mismatch"}:
            raise ArtifactValidationError(
                f"sample[{index}].failure_class is impossible for a 2xx status"
            )
        elif (
            failure_class == "invalid_response"
            and value["upstream_proof_sha256"] != hashlib.sha256(b"").hexdigest()
        ):
            raise ArtifactValidationError(
                f"sample[{index}].failure_class invalid_response requires an empty proof"
            )
    if value["leg"] == "baseline":
        if (
            value["decision"] != "direct"
            or value["control_mode"] != "direct"
            or value["evidence_outcome"] != "not_applicable"
            or value["receipt_outcome"] != "not_applicable"
        ):
            raise ArtifactValidationError(f"baseline sample[{index}] contains Hawk assertions")
    else:
        if (
            value["decision"] == "direct"
            or value["control_mode"] == "direct"
            or value["evidence_outcome"] == "not_applicable"
            or value["receipt_outcome"] == "not_applicable"
        ):
            raise ArtifactValidationError(
                f"Hawk sample[{index}] contains baseline-only assertions"
            )
    return value


def validate_benchmark_artifacts(
    *,
    metadata: Any,
    samples: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    valid_metadata = validate_metadata(metadata)
    if not isinstance(samples, list):
        raise ArtifactValidationError("samples must be a list")
    valid_samples = [_validate_sample(sample, index=index) for index, sample in enumerate(samples)]

    pair_count = valid_metadata["warmup_pairs"] + valid_metadata["measured_pairs"]
    expected_sample_count = pair_count * 2
    if len(valid_samples) != expected_sample_count:
        raise ArtifactValidationError(
            f"sample count mismatch: expected {expected_sample_count}, got {len(valid_samples)}"
        )
    if [sample["sequence_index"] for sample in valid_samples] != list(range(expected_sample_count)):
        raise ArtifactValidationError("sample sequence_index values must be contiguous and ordered")

    by_pair: dict[int, list[dict[str, Any]]] = defaultdict(list)
    metadata_sha256 = hashlib.sha256(canonical_json_bytes(valid_metadata)).hexdigest()
    run_started = _parse_timestamp(valid_metadata["started_at"], label="started_at")
    run_finished = _parse_timestamp(valid_metadata["finished_at"], label="finished_at")
    for sample in valid_samples:
        if sample["run_id"] != valid_metadata["run_id"]:
            raise ArtifactValidationError("sample run_id does not match metadata")
        if sample["request_bytes"] != valid_metadata["payload"]["bytes"]:
            raise ArtifactValidationError("sample payload byte count does not match metadata")
        if sample["request_payload_sha256"] != valid_metadata["payload"]["sha256"]:
            raise ArtifactValidationError("sample payload hash does not match metadata")
        if sample["metadata_sha256"] != metadata_sha256:
            raise ArtifactValidationError("sample metadata binding does not match metadata.json")
        if (
            sample["outcome"] == "success"
            and sample["upstream_proof_sha256"]
            != valid_metadata["upstream_stub"]["response_proof_sha256"]
        ):
            raise ArtifactValidationError("sample upstream proof does not match the deterministic stub")
        if (
            sample["failure_class"] == "upstream_proof_mismatch"
            and sample["upstream_proof_sha256"]
            == valid_metadata["upstream_stub"]["response_proof_sha256"]
        ):
            raise ArtifactValidationError(
                "sample failure_class claims an upstream proof mismatch for the expected proof"
            )
        sample_started = _parse_timestamp(
            sample["request_started_at"],
            label="request_started_at",
        )
        sample_finished = _parse_timestamp(
            sample["request_finished_at"],
            label="request_finished_at",
        )
        if sample_started < run_started or sample_finished > run_finished:
            raise ArtifactValidationError("sample timestamps fall outside metadata run bounds")
        by_pair[sample["pair_index"]].append(sample)

    if set(by_pair) != set(range(pair_count)):
        raise ArtifactValidationError("pair indexes are incomplete or non-contiguous")
    stage_pair_intervals: dict[bool, list[tuple[datetime, datetime]]] = {
        True: [],
        False: [],
    }
    for pair_index in range(pair_count):
        pair = by_pair[pair_index]
        expected_pair_id = f"pair-{pair_index:06d}"
        if len(pair) != 2:
            raise ArtifactValidationError(f"pair {pair_index} does not contain exactly two legs")
        expected_legs = (
            ["baseline", "hawk"]
            if pair_index % 2 == 0
            else ["hawk", "baseline"]
        )
        actual_legs = [sample["leg"] for sample in pair]
        if actual_legs != expected_legs:
            raise ArtifactValidationError(
                f"pair {pair_index} is not in the required alternating leg order"
            )
        if any(sample["pair_id"] != expected_pair_id for sample in pair):
            raise ArtifactValidationError(f"pair {pair_index} has inconsistent pair_id")
        expected_warmup = pair_index < valid_metadata["warmup_pairs"]
        if any(sample["excluded_warmup"] is not expected_warmup for sample in pair):
            raise ArtifactValidationError(f"pair {pair_index} warmup marker is inconsistent")
        if len({sample["request_payload_sha256"] for sample in pair}) != 1:
            raise ArtifactValidationError(f"pair {pair_index} payload hashes differ")
        if len({sample["request_bytes"] for sample in pair}) != 1:
            raise ArtifactValidationError(f"pair {pair_index} payload byte counts differ")
        first_finished = _parse_timestamp(
            pair[0]["request_finished_at"],
            label="request_finished_at",
        )
        second_started = _parse_timestamp(
            pair[1]["request_started_at"],
            label="request_started_at",
        )
        if first_finished > second_started:
            raise ArtifactValidationError(
                f"pair {pair_index} timestamp chronology contradicts sequential leg order"
            )
        pair_started = _parse_timestamp(
            pair[0]["request_started_at"],
            label="request_started_at",
        )
        pair_finished = _parse_timestamp(
            pair[1]["request_finished_at"],
            label="request_finished_at",
        )
        stage_pair_intervals[expected_warmup].append((pair_started, pair_finished))
    warmup_samples = [sample for sample in valid_samples if sample["excluded_warmup"]]
    measured_samples = [sample for sample in valid_samples if not sample["excluded_warmup"]]
    if warmup_samples:
        last_warmup_finish = max(
            _parse_timestamp(sample["request_finished_at"], label="request_finished_at")
            for sample in warmup_samples
        )
        first_measured_start = min(
            _parse_timestamp(sample["request_started_at"], label="request_started_at")
            for sample in measured_samples
        )
        if last_warmup_finish > first_measured_start:
            raise ArtifactValidationError(
                "warmup samples must finish before measured samples start"
            )
    for intervals in stage_pair_intervals.values():
        active_finishes: list[datetime] = []
        for interval_start, interval_finish in sorted(intervals):
            while active_finishes and active_finishes[0] <= interval_start:
                heapq.heappop(active_finishes)
            if interval_finish > interval_start:
                heapq.heappush(active_finishes, interval_finish)
            if len(active_finishes) > valid_metadata["concurrency"]:
                raise ArtifactValidationError(
                    "raw pair overlap exceeds recorded metadata concurrency"
                )
    return valid_metadata, valid_samples


def _nearest_rank(values: list[float], percentile: int) -> float:
    if not values:
        raise ArtifactValidationError("cannot calculate a percentile without samples")
    ordered = sorted(float(value) for value in values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return round(ordered[rank - 1], 6)


def _latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": _nearest_rank(values, 50),
        "p95": _nearest_rank(values, 95),
        "p99": _nearest_rank(values, 99),
    }


def _optional_latency_summary(values: list[float]) -> dict[str, float] | None:
    return _latency_summary(values) if values else None


def _counter_dict(values: list[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(value) for value in values).items()))


def performance_claim_reasons(
    *,
    eligible_pairs: int,
    measured_pairs: int,
    excluded_pairs: int,
    metadata: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if eligible_pairs == 0:
        reasons.append("no_valid_comparison_pairs")
    elif eligible_pairs < MIN_PUBLISHABLE_MEASURED_PAIRS:
        reasons.append("insufficient_eligible_pairs")
    if excluded_pairs > 0:
        reasons.append("excluded_comparison_pairs")
    source = metadata["source"]
    if not source["performance_claim_eligible"]:
        reasons.append(source["ineligibility_reason"])
    run_integrity = metadata["run_integrity"]
    if not run_integrity["source_snapshot_stable"]:
        reasons.append("source_changed_during_run")
    if not run_integrity["implementation_snapshot_stable"]:
        reasons.append("implementation_changed_during_run")
    if measured_pairs < MIN_PUBLISHABLE_MEASURED_PAIRS and (
        "insufficient_eligible_pairs" not in reasons
        and "no_valid_comparison_pairs" not in reasons
    ):
        reasons.append("insufficient_measured_pairs")
    return reasons


def build_benchmark_summary(
    *,
    metadata: Any,
    samples: Any,
    raw_samples: bytes,
) -> dict[str, Any]:
    valid_metadata, valid_samples = validate_benchmark_artifacts(
        metadata=metadata,
        samples=samples,
    )
    if not isinstance(raw_samples, bytes):
        raise ArtifactValidationError("raw_samples must be bytes")
    measured = [sample for sample in valid_samples if not sample["excluded_warmup"]]
    baseline = [sample for sample in measured if sample["leg"] == "baseline"]
    hawk = [sample for sample in measured if sample["leg"] == "hawk"]
    baseline_by_pair = {sample["pair_index"]: sample for sample in baseline}
    hawk_by_pair = {sample["pair_index"]: sample for sample in hawk}
    pair_indexes = sorted(set(baseline_by_pair) | set(hawk_by_pair))
    if set(baseline_by_pair) != set(hawk_by_pair):
        raise ArtifactValidationError("measured pairs are incomplete")
    expected_proof = valid_metadata["upstream_stub"]["response_proof_sha256"]
    governance_expectations = valid_metadata["governance_expectations"]
    comparison_pair_indexes: list[int] = []
    excluded_pair_reasons: Counter[str] = Counter()
    for pair_index in pair_indexes:
        baseline_sample = baseline_by_pair[pair_index]
        hawk_sample = hawk_by_pair[pair_index]
        reasons: list[str] = []
        if baseline_sample["outcome"] != "success":
            reasons.append(f"baseline:{baseline_sample['failure_class']}")
        if hawk_sample["outcome"] != "success":
            reasons.append(f"hawk:{hawk_sample['failure_class']}")
        elif hawk_sample["upstream_proof_sha256"] != expected_proof:
            reasons.append("hawk:unreconciled_upstream_proof")
        else:
            for field in (
                "decision",
                "control_mode",
                "evidence_outcome",
                "receipt_outcome",
            ):
                if hawk_sample[field] != governance_expectations[field]:
                    reasons.append(f"hawk:{field}_not_expected")
        if reasons:
            excluded_pair_reasons.update(reasons)
        else:
            comparison_pair_indexes.append(pair_index)
    comparison_baseline = [
        baseline_by_pair[pair_index] for pair_index in comparison_pair_indexes
    ]
    comparison_hawk = [
        hawk_by_pair[pair_index] for pair_index in comparison_pair_indexes
    ]
    overheads = [
        float(hawk_by_pair[index]["e2e_ms"])
        - float(baseline_by_pair[index]["e2e_ms"])
        for index in comparison_pair_indexes
    ]

    starts = [
        _parse_timestamp(sample["request_started_at"], label="request_started_at")
        for sample in measured
    ]
    finishes = [
        _parse_timestamp(sample["request_finished_at"], label="request_finished_at")
        for sample in measured
    ]
    measurement_window = (max(finishes) - min(starts)).total_seconds()
    if measurement_window <= 0:
        raise ArtifactValidationError("measured sample window must be positive")

    def failure_rate(items: list[dict[str, Any]]) -> float:
        failures = sum(sample["outcome"] == "failure" for sample in items)
        return round(failures / len(items), 6)

    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "run_id": valid_samples[0]["run_id"],
        "raw_samples_sha256": hashlib.sha256(raw_samples).hexdigest(),
        "sample_counts": {
            "total": len(valid_samples),
            "excluded_warmup": len(valid_samples) - len(measured),
            "measured": len(measured),
            "measured_pairs": len(pair_indexes),
        },
        "comparison": {
            "eligible_pairs": len(comparison_pair_indexes),
            "excluded_pairs": len(pair_indexes) - len(comparison_pair_indexes),
            "excluded_pair_reasons": dict(sorted(excluded_pair_reasons.items())),
            "latency_ms": {
                "baseline": _optional_latency_summary(
                    [sample["e2e_ms"] for sample in comparison_baseline]
                ),
                "hawk": _optional_latency_summary(
                    [sample["e2e_ms"] for sample in comparison_hawk]
                ),
            },
            "observed_paired_overhead_ms": _optional_latency_summary(overheads),
        },
        "diagnostic_attempt_latency_ms": {
            "all_measured": {
                "baseline": _latency_summary(
                    [sample["e2e_ms"] for sample in baseline]
                ),
                "hawk": _latency_summary([sample["e2e_ms"] for sample in hawk]),
            },
            "failed_attempts": {
                "baseline": _optional_latency_summary(
                    [
                        sample["e2e_ms"]
                        for sample in baseline
                        if sample["outcome"] == "failure"
                    ]
                ),
                "hawk": _optional_latency_summary(
                    [
                        sample["e2e_ms"]
                        for sample in hawk
                        if sample["outcome"] == "failure"
                    ]
                ),
            },
        },
        "measurement_window_seconds": round(measurement_window, 6),
        "throughput_rps": {
            "measured_requests": round(len(measured) / measurement_window, 6),
            "baseline": round(len(baseline) / measurement_window, 6),
            "hawk": round(len(hawk) / measurement_window, 6),
        },
        "failure_rate": {
            "all_measured": failure_rate(measured),
            "baseline": failure_rate(baseline),
            "hawk": failure_rate(hawk),
        },
        "status_counts": {
            "baseline": _counter_dict([sample["status_code"] for sample in baseline]),
            "hawk": _counter_dict([sample["status_code"] for sample in hawk]),
        },
        "decision_counts": _counter_dict([sample["decision"] for sample in hawk]),
        "control_mode_counts": _counter_dict([sample["control_mode"] for sample in hawk]),
        "evidence_outcome_counts": _counter_dict(
            [sample["evidence_outcome"] for sample in hawk]
        ),
        "receipt_outcome_counts": _counter_dict(
            [sample["receipt_outcome"] for sample in hawk]
        ),
    }
    claim_reasons = performance_claim_reasons(
        eligible_pairs=len(comparison_pair_indexes),
        measured_pairs=len(pair_indexes),
        excluded_pairs=len(pair_indexes) - len(comparison_pair_indexes),
        metadata=valid_metadata,
    )
    summary["performance_claim"] = {
        "eligible": not claim_reasons,
        "reasons": claim_reasons,
    }
    return summary


def _load_benchmark_run(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], bytes]:
    metadata_path = run_dir / "metadata.json"
    samples_path = run_dir / "samples.ndjson"
    if not metadata_path.is_file() or not samples_path.is_file():
        raise ArtifactValidationError("benchmark run requires metadata.json and samples.ndjson")
    try:
        raw_metadata = metadata_path.read_bytes()
        metadata = json.loads(raw_metadata)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError("metadata.json is not valid UTF-8 JSON") from exc
    if raw_metadata != canonical_json_bytes(metadata) + b"\n":
        raise ArtifactValidationError("metadata.json is not canonical JSON")
    try:
        raw_samples = samples_path.read_bytes()
    except OSError as exc:
        raise ArtifactValidationError("samples.ndjson could not be read") from exc
    if not raw_samples or not raw_samples.endswith(b"\n"):
        raise ArtifactValidationError("samples.ndjson must be non-empty and newline terminated")
    samples: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw_samples.splitlines(), start=1):
        if not raw_line.strip():
            raise ArtifactValidationError(
                f"samples.ndjson contains a blank line at {line_number}"
            )
        try:
            sample = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArtifactValidationError(
                f"samples.ndjson line {line_number} is invalid JSON"
            ) from exc
        if canonical_json_bytes(sample) != raw_line:
            raise ArtifactValidationError(
                f"samples.ndjson line {line_number} is not canonical JSON"
            )
        samples.append(sample)
    return metadata, samples, raw_samples


def write_benchmark_summary(run_dir: Path) -> dict[str, Any]:
    metadata, samples, raw_samples = _load_benchmark_run(run_dir)
    result = build_benchmark_summary(
        metadata=metadata,
        samples=samples,
        raw_samples=raw_samples,
    )
    (run_dir / "summary.json").write_bytes(canonical_json_bytes(result) + b"\n")
    return result


def verify_benchmark_artifacts(run_dir: Path) -> dict[str, Any]:
    summary_path = run_dir / "summary.json"
    if not summary_path.is_file():
        raise ArtifactValidationError("benchmark run requires summary.json")
    raw_samples_path = run_dir / "samples.ndjson"
    try:
        raw_samples = raw_samples_path.read_bytes()
        existing = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError("summary or raw samples could not be read") from exc
    expected_checksum = existing.get("raw_samples_sha256") if isinstance(existing, dict) else None
    actual_checksum = hashlib.sha256(raw_samples).hexdigest()
    if expected_checksum != actual_checksum:
        raise ArtifactValidationError("raw sample checksum does not match summary")
    metadata, samples, canonical_raw_samples = _load_benchmark_run(run_dir)
    rebuilt = build_benchmark_summary(
        metadata=metadata,
        samples=samples,
        raw_samples=canonical_raw_samples,
    )
    if existing != rebuilt:
        raise ArtifactValidationError("summary does not match the validated raw samples")
    if summary_path.read_bytes() != canonical_json_bytes(existing) + b"\n":
        raise ArtifactValidationError("summary.json is not canonical JSON")
    return rebuilt


@dataclass
class SuiteResult:
    name: str
    command: list[str]
    cwd: Path
    return_code: int
    duration_seconds: float
    error: str | None = None


def _run_suite(*, name: str, command: list[str], cwd: Path, env: dict[str, str]) -> SuiteResult:
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, cwd=cwd, env=env, check=False)
        return_code = completed.returncode
        error = None
    except FileNotFoundError as exc:
        return_code = 127
        error = str(exc)
    duration = time.perf_counter() - started
    return SuiteResult(
        name=name,
        command=command,
        cwd=cwd,
        return_code=return_code,
        duration_seconds=duration,
        error=error,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run enterprise test suites and print summary.")
    parser.add_argument(
        "--verify-benchmark-run",
        type=Path,
        default=None,
        help="Validate metadata/raw samples/checksum and reproduce an existing benchmark summary.",
    )
    parser.add_argument(
        "--include-extension-e2e",
        action="store_true",
        help="Include extension Playwright e2e run (requires extension dependencies + headed browser support).",
    )
    args = parser.parse_args()

    if args.verify_benchmark_run is not None:
        if args.include_extension_e2e:
            parser.error("--include-extension-e2e cannot be combined with --verify-benchmark-run")
        try:
            result = verify_benchmark_artifacts(args.verify_benchmark_run.resolve())
        except ArtifactValidationError as exc:
            print(f"Benchmark artifact verification failed: {exc}", file=sys.stderr)
            return 1
        print(canonical_json_bytes(result).decode("ascii"))
        return 0

    repo_root = Path(__file__).resolve().parents[2]
    api_env = os.environ.copy()
    api_env["PYTHONPATH"] = "apps/api"
    api_env["TEST_PROFILE"] = api_env.get("TEST_PROFILE", "unit")
    extension_env = os.environ.copy()

    suites: list[tuple[str, list[str], Path, dict[str, str]]] = [
        (
            "api_contracts",
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "apps/api/tests/test_api_contracts.py",
                "apps/api/tests/test_contract_ai_systems.py",
                "apps/api/tests/test_contract_policies.py",
                "apps/api/tests/test_contract_ai_iam.py",
            ],
            repo_root,
            api_env,
        ),
        (
            "browser_extension_api_integration",
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "apps/api/tests/test_extension_service_unit.py",
                "apps/api/tests/test_extension_browser_telemetry.py",
            ],
            repo_root,
            api_env,
        ),
        (
            "llm_gateway_integration",
            ["python3", "-m", "pytest", "-q", "apps/api/tests/test_llm_gateway_integration.py"],
            repo_root,
            api_env,
        ),
        (
            "connectors_polling_normalization",
            ["python3", "-m", "pytest", "-q", "apps/api/tests/test_integrations_connectors.py"],
            repo_root,
            api_env,
        ),
        (
            "findings_generation",
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "apps/api/tests/test_findings_pipeline.py",
                "apps/api/tests/test_findings_traceability.py",
            ],
            repo_root,
            api_env,
        ),
        (
            "simulation_auto_scheduler",
            ["python3", "-m", "pytest", "-q", "apps/api/tests/test_simulation_scheduler.py"],
            repo_root,
            api_env,
        ),
        (
            "brain_citation_refusal",
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "apps/api/tests/test_brain_golden.py",
                "apps/api/tests/test_brain_findings_analyze.py",
            ],
            repo_root,
            api_env,
        ),
        (
            "auditor_snapshot_integrity",
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "apps/api/tests/test_auditor_defensibility.py",
                "apps/api/tests/test_auditor_snapshot_scope_rules.py",
            ],
            repo_root,
            api_env,
        ),
        (
            "chaos_fail_secure",
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "apps/api/tests/test_control_plane_health_dependency.py",
                "apps/api/tests/test_fail_secure_mode.py",
                "apps/api/tests/test_fail_secure_critical_routes.py",
                "apps/api/tests/test_celery_hardening.py",
            ],
            repo_root,
            api_env,
        ),
    ]

    if args.include_extension_e2e:
        suites.append(
            (
                "browser_extension_playwright_e2e",
                ["npm", "run", "test:e2e"],
                repo_root / "extension",
                extension_env,
            )
        )

    results: list[SuiteResult] = []
    for name, command, cwd, env in suites:
        print(f"\n=== Running suite: {name} ===")
        result = _run_suite(name=name, command=command, cwd=cwd, env=env)
        results.append(result)
        status = "PASS" if result.return_code == 0 else "FAIL"
        print(f"=== Suite result: {name} -> {status} ({result.duration_seconds:.2f}s) ===")

    total_duration = sum(result.duration_seconds for result in results)
    failures = [result for result in results if result.return_code != 0]

    print("\n===== Enterprise Test Report Summary =====")
    for result in results:
        status = "PASS" if result.return_code == 0 else "FAIL"
        command_preview = " ".join(result.command)
        print(f"{status:4} | {result.name:36} | {result.duration_seconds:7.2f}s | {command_preview}")
        if result.error:
            print(f"      error: {result.error}")

    print("------------------------------------------")
    print(f"Total suites: {len(results)}")
    print(f"Passed: {len(results) - len(failures)}")
    print(f"Failed: {len(failures)}")
    print(f"Total duration: {total_duration:.2f}s")

    if failures:
        print("\nFailed suites:")
        for result in failures:
            print(f"- {result.name} (exit={result.return_code})")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
