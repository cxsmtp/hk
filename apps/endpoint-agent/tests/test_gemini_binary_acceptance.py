from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import re

import pytest

from hawk_endpoint_agent.native_control.gemini_acceptance import (
    GeminiBinaryAcceptanceReport,
    _classify_real_model_none_result,
    run_gemini_binary_acceptance,
)


def test_gemini_acceptance_report_requires_real_binary_evidence_for_promotion() -> None:
    report = GeminiBinaryAcceptanceReport.empty("0.54.4", diagnostic="not run")

    assert report.passed is False
    assert report.accepted_capabilities == ()
    assert report.maturity == "experimental"
    assert report.diagnostics == ("not run",)


def test_gemini_acceptance_target_binds_exact_version_and_package_integrity(
    tmp_path: Path,
) -> None:
    report = run_gemini_binary_acceptance(
        tmp_path / "missing-gemini",
        expected_version="0.55.1",
        expected_package_integrity=(
            "sha512-leEv91V7J3YWhZdXqYIj4nTl0hXl8oNos5aVR0whPCFqVbRvoFPTzaQOHdI2"
            "UIT1wGgp+XdCi4qUrFDnUFN7RQ=="
        ),
    )

    assert report.passed is False
    assert report.diagnostics == ("gemini binary unavailable",)

    with pytest.raises(ValueError, match="expected_version_invalid"):
        run_gemini_binary_acceptance(
            tmp_path / "missing-gemini",
            expected_version="latest",
            expected_package_integrity="sha512-valid",
        )

    with pytest.raises(ValueError, match="expected_package_integrity_invalid"):
        run_gemini_binary_acceptance(
            tmp_path / "missing-gemini",
            expected_version="0.55.1",
            expected_package_integrity="unknown",
        )


def test_real_model_none_classifier_requires_authenticated_selection_without_tool_entry() -> None:
    assert _classify_real_model_none_result(
        returncode=0,
        stdout='{"response":"model completed without tools"}',
        events=[{"provider_event_type": "before_tool_selection"}],
        marker_exists=False,
    ) == "verified:real_model_none_prevented_tool_call"
    assert _classify_real_model_none_result(
        returncode=0,
        stdout='{"response":"unexpected tool"}',
        events=[
            {"provider_event_type": "before_tool_selection"},
            {"provider_event_type": "before_tool"},
        ],
        marker_exists=False,
    ) == "failed:real_model_none_tool_executed"
    assert _classify_real_model_none_result(
        returncode=1,
        stdout='{"error":"invalid credential"}',
        events=[],
        marker_exists=False,
    ) == "unverified:real_model_request_failed"


def test_installed_gemini_binary_acceptance() -> None:
    binary = Path(
        os.environ.get(
            "HAWK_GEMINI_ACCEPTANCE_BINARY",
            "/private/tmp/hawk-gemini-cli-0.54.4/node_modules/.bin/gemini",
        )
    )
    if not binary.is_file():
        pytest.skip("exact Gemini CLI acceptance binary is not installed")

    report = run_gemini_binary_acceptance(binary)
    if os.environ.get("HAWK_GEMINI_ACCEPTANCE_PRINT") == "1":
        print(json.dumps({**asdict(report), "passed": report.passed}, sort_keys=True))

    assert re.fullmatch(r"\d+\.\d+\.\d+", report.provider_version)
    assert report.provider_version == "0.54.4"
    assert report.runtime_binding_version == report.provider_version
    assert report.real_binary_invoked is True
    assert report.package_source == "@google/gemini-cli@0.54.4"
    assert report.session_start_observed is True
    assert report.before_agent_observed is True
    assert report.before_model_observed is True
    assert report.before_tool_selection_observed is True
    assert report.before_agent_status == "verified:block_before_model_or_tool"
    assert report.before_model_status == "verified:block_before_tool"
    assert report.before_tool_selection_status == "verified:filter_only_not_exact_authorization"
    assert report.before_tool_allow_observed is True
    assert report.allowed_action_executed is True
    assert report.after_tool_correlated is True
    assert report.after_model_observed is True
    assert report.after_agent_observed is True
    assert report.session_end_observed is True
    assert report.before_tool_block_observed is True
    assert report.blocked_action_executed is False
    assert report.json_deny_blocked is True
    assert report.exit_code_two_blocked is True
    assert report.timeout_behavior in {"failed_closed", "provider_warning_fail_open"}
    assert report.malformed_stdout_behavior in {
        "provider_warning_fail_open",
        "provider_mixed_hawk_serializer_fail_closed",
        "provider_rejected_all_malformed_output",
    }
    assert report.serializer_failure_status == "verified:exit_2_fail_closed"
    assert report.input_mutation_supported is False
    assert report.measured_callback_sample_count > 0
    assert report.measured_callback_p95_ms < 4_000
    assert report.exact_version_verified is True
    assert report.forged_callback_rejected is True
    assert report.replay_rejected is True
    assert report.exact_tool_input_bound is True
    assert report.shell_status == "verified:allow_block"
    assert report.file_read_status == "verified:observe"
    assert report.file_write_status == "verified:allow_block"
    assert report.mcp_read_status == "verified:observe"
    assert report.mcp_write_status == "verified:allow_block"
    assert report.default_mode_status == "verified:before_tool_blocked"
    assert report.auto_edit_mode_status == "verified:before_tool_blocked"
    assert report.plan_mode_status == "verified:before_tool_blocked"
    assert report.yolo_mode_status == "verified:before_tool_blocked"
    assert report.provider_policy_status == "verified:native_deny_monotonic"
    assert report.cli_admin_policy_status == "unverified:admin_tier_not_enforced"
    assert report.backend_unavailable_status == "verified:failed_closed"
    assert report.signal_handling_status == "verified:no_partial_stdout"
    assert report.tail_call_status == "verified:reentered_before_tool_and_blocked"
    assert report.hook_composition_status in {
        "verified:post_hawk_mutation_possible",
        "verified:post_hawk_mutation_not_applied",
    }
    assert report.notification_status == "verified:observed_advisory"
    assert report.tool_selection_none_fixture_status in {
        "observed:none_fixture_suppressed_tool_call_not_model_proof",
        "unverified:fake_model_bypassed_selection_contract",
        "unverified:before_tool_still_observed",
    }
    assert report.tool_selection_none_status == "unverified:real_model_acceptance_not_requested"
    assert report.admin_policy_status == "unverified:tenant_evidence_not_supplied"
    assert report.managed_launcher_artifact_status == "verified:hash_pinned_artifact_rendered"
    assert report.managed_launcher_deployment_status == "unverified:mdm_deployment_evidence_not_supplied"
    assert report.accepted_capabilities
    assert not report.diagnostics, report.diagnostics
    assert report.maturity == "experimental"
    assert report.passed is False
