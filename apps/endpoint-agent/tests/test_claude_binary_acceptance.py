from __future__ import annotations

import os
from pathlib import Path

import pytest

from hawk_endpoint_agent.native_control.claude_acceptance import run_claude_binary_acceptance


CLAUDE_BINARY = Path(
    os.environ.get("HAWK_CLAUDE_BINARY", str(Path.home() / ".local" / "bin" / "claude"))
)


@pytest.mark.skipif(not CLAUDE_BINARY.is_file(), reason="installed Claude Code binary unavailable")
def test_installed_claude_2_1_183_honors_signed_hawk_allow_block_and_timeout() -> None:
    report = run_claude_binary_acceptance(CLAUDE_BINARY)

    assert report.provider_version == "2.1.183"
    assert report.signed_allow is True
    assert report.allowed_action_executed is True
    assert report.allow_post_action_correlated is True
    assert report.post_action_evidence_quality == "provider_reported"
    assert report.signed_block is True
    assert report.blocked_action_executed is False
    assert report.block_survived_mutator_first is True
    assert report.block_survived_mutator_last is True
    assert report.timeout_failed_closed is True
    assert report.config_tamper_detected is True
    assert report.uninstall_preserved_customer_hooks is True
    assert report.measured_callback_p95_ms < 4_000
    assert report.runtime_binding_version == report.provider_version
    assert report.safe_mode_user_hook_bypassed is True
    assert report.bare_mode_hook_bypassed is True
    assert report.exact_version_verified is True
    assert report.default_mode_pretool_blocked is True
    assert report.accept_edits_pretool_blocked is True
    assert report.bypass_permissions_pretool_blocked is True
    assert report.dangerous_skip_pretool_blocked is True
    assert report.plan_mode_status in {"pretool_blocked", "provider_blocked_before_hook"}
    assert report.permission_request_status == "observed_interactive", "\n".join(report.diagnostics)
    assert report.permission_request_correlated is True
    assert report.permission_context_recorded is True
    assert report.provider_allow_could_not_override_block is True
    assert report.approval_mutation_required_reauthorization is True
    assert report.exact_parameter_binding is True
    assert report.user_prompt_submit_observed is True
    assert report.user_prompt_allow_reached_model is True
    assert report.user_prompt_block_reached_model is False
    assert report.user_prompt_blocked_before_model is True
    assert report.mcp_read_allowed is True
    assert report.mcp_read_post_action_correlated is True
    assert report.mcp_write_blocked is True
    assert report.mcp_write_marker_created is False
    assert report.agent_allow_pretool_observed is True
    assert report.agent_lineage_observed is True
    assert report.agent_block_pretool_observed is True
    assert report.blocked_agent_spawned is False
    assert report.remote_control_status in {
        "verified:local_runtime_callback",
        "unverified:interactive_authenticated_session_required",
        "unverified:not_supported_by_binary",
    }
    assert report.managed_safe_mode_status in {
        "verified:managed_source_allow_block",
        "unverified:managed_access_required",
        "unverified:transaction_not_run",
    }
    assert report.config_change_status in {"observed_secondary_signal", "not_observed_experimental"}
    assert report.approval_action_executed is False
    assert report.file_read_post_action_correlated is True
    assert report.file_write_post_action_correlated is True
    assert report.post_failure_correlated is True
    assert report.background_pretool_blocked is True
    assert report.session_start_observed is True
    assert report.session_end_observed is True
    assert report.input_mutation_supported is False
    assert report.measured_callback_sample_count > 0
    assert report.measured_callback_p50_ms <= report.measured_callback_p95_ms
    assert report.measured_callback_p95_ms <= report.measured_callback_p99_ms
    assert report.passed is True
