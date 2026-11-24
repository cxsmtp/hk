from __future__ import annotations

from dataclasses import replace

import pytest

from app.core.control_engine.authorization import authorize_ai_action
from app.services.native_control.adapter_contract import AdapterPipelineContext
from app.services.native_control.claude_adapter import ClaudeAdapter
from app.services.native_control.contracts import ActionClass
from app.services.native_control.cross_provider_conformance import (
    ConformanceAvailability,
    CrossProviderConformanceService,
)
from app.services.native_control.cursor_adapter import CursorAdapter
from app.services.native_control.gemini_cli_adapter import GeminiCliAdapter
from app.services.native_control.openai_adapters import (
    OpenAIAgentsSDKControlAdapter,
    OpenAIDirectAPIControlAdapter,
)


TENANT_ID = "tenant-conformance"
POLICY = {"base_decision": "allow", "dependencies_healthy": True}


def _context(*, provider: str, version: str, event_id: str) -> AdapterPipelineContext:
    base = AdapterPipelineContext.reference(
        tenant_id=TENANT_ID,
        integration_instance_id=f"{provider}-integration",
        provider_event_id=event_id,
        policy_profile=POLICY,
    )
    return replace(
        base,
        provider_version=version,
        chain_id="conformance-chain",
        session_id="conformance-session",
        resolved_actor={
            "identity_id": "verified-operator",
            "identity_type": "human",
            "authority_type": "authenticated_user",
            "authority_source": "enterprise_directory",
        },
    )


def _service() -> CrossProviderConformanceService:
    return CrossProviderConformanceService()


def test_equivalent_command_fixtures_share_action_class_and_policy_material() -> None:
    service = _service()
    command = "git push origin main"
    cases = (
        (
            ClaudeAdapter(),
            _context(provider="claude", version="2.1.183", event_id="claude-command"),
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": "/workspace",
                "target": "/workspace",
                "persistent_side_effect": True,
            },
        ),
        (
            GeminiCliAdapter(),
            _context(provider="gemini", version="0.54.4", event_id="gemini-command"),
            {
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": command},
                "cwd": "/workspace",
                "target": "/workspace",
                "persistent_side_effect": True,
            },
        ),
        (
            CursorAdapter(),
            _context(provider="cursor", version="2026.08.11-e8db854", event_id="cursor-command"),
            {
                "hook_event_name": "beforeShellExecution",
                "command": command,
                "cwd": "/workspace",
                "target": "/workspace",
                "persistent_side_effect": True,
            },
        ),
        (
            OpenAIDirectAPIControlAdapter(),
            _context(provider="openai", version="1.0.0", event_id="openai-command"),
            {
                "event_type": "tool_proposal",
                "tool_class": "local_shell",
                "tool_name": "Bash",
                "arguments": {"command": command},
                "target": "/workspace",
                "destination": "local",
                "persistent_side_effect": True,
            },
        ),
    )

    outcomes = [service.normalize(adapter, context, payload) for adapter, context, payload in cases]

    assert {outcome.action_class for outcome in outcomes} == {ActionClass.COMMAND}
    assert all(
        outcome.policy_relevant_material == outcomes[0].policy_relevant_material
        for outcome in outcomes[1:2]
    )
    assert all(
        outcome.availability is ConformanceAvailability.RESOLVED
        for outcome in outcomes[:2]
    )
    assert outcomes[2].availability is ConformanceAvailability.UNKNOWN
    # The Direct API adapter can parse this tool proposal but has no reviewed
    # local-shell capability; semantic normalization must not upgrade that.
    assert outcomes[3].availability is ConformanceAvailability.UNKNOWN
    assert service.equivalent(outcomes[0], outcomes[1]) is True
    assert outcomes[0].authorization_response == outcomes[1].authorization_response
    assert service.equivalent(outcomes[0], outcomes[3]) is False
    assert len({outcome.canonical_action_hash for outcome in outcomes}) == len(outcomes)


def test_equivalent_file_read_and_write_fixtures_preserve_distinct_canonical_classes() -> None:
    service = _service()
    read_cases = (
        (ClaudeAdapter(), _context(provider="claude", version="2.1.183", event_id="claude-read"), {
            "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/workspace/README.md"},
        }),
        (GeminiCliAdapter(), _context(provider="gemini", version="0.54.4", event_id="gemini-read"), {
            "hook_event_name": "BeforeTool", "tool_name": "read_file", "tool_input": {"file_path": "/workspace/README.md"},
        }),
        (CursorAdapter(), _context(provider="cursor", version="2026.08.11-e8db854", event_id="cursor-read"), {
            "hook_event_name": "beforeReadFile", "file_path": "/workspace/README.md",
        }),
    )
    write_cases = (
        (ClaudeAdapter(), _context(provider="claude", version="2.1.183", event_id="claude-write"), {
            "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "/workspace/out.txt", "content": "safe"},
        }),
        (GeminiCliAdapter(), _context(provider="gemini", version="0.54.4", event_id="gemini-write"), {
            "hook_event_name": "BeforeTool", "tool_name": "write_file", "tool_input": {"file_path": "/workspace/out.txt", "content": "safe"},
        }),
        (CursorAdapter(), _context(provider="cursor", version="2026.08.11-e8db854", event_id="cursor-write"), {
            "hook_event_name": "afterFileEdit", "file_path": "/workspace/out.txt",
        }),
    )

    reads = [service.normalize(adapter, context, payload) for adapter, context, payload in read_cases]
    writes = [service.normalize(adapter, context, payload) for adapter, context, payload in write_cases]

    assert {outcome.action_class for outcome in reads} == {ActionClass.FILE_READ}
    assert {outcome.action_class for outcome in writes} == {ActionClass.FILE_WRITE}
    assert service.equivalent(reads[0], reads[1]) is True
    assert reads[0].authorization_response == reads[1].authorization_response
    assert service.equivalent(writes[0], writes[1]) is True
    assert writes[0].authorization_response == writes[1].authorization_response
    assert reads[2].availability is ConformanceAvailability.UNKNOWN
    assert writes[2].availability is ConformanceAvailability.UNKNOWN
    assert service.equivalent(reads[0], writes[0]) is False


def test_mcp_api_function_and_delegation_preserve_action_class_without_false_lifecycle_parity() -> None:
    service = _service()
    mcp_cases = (
        (ClaudeAdapter(), _context(provider="claude", version="2.1.183", event_id="claude-mcp"), {
            "hook_event_name": "PreToolUse", "tool_name": "mcp__github__get_issue", "tool_input": {"repo": "hawk"}, "target": "hawk",
        }),
        (GeminiCliAdapter(), _context(provider="gemini", version="0.54.4", event_id="gemini-mcp"), {
            "hook_event_name": "BeforeTool", "tool_name": "mcp_github_get_issue", "tool_input": {"repo": "hawk"}, "target": "hawk",
        }),
        (CursorAdapter(), _context(provider="cursor", version="2026.08.11-e8db854", event_id="cursor-mcp"), {
            "hook_event_name": "beforeMCPExecution", "tool_name": "github_get_issue", "tool_input": {"repo": "hawk"}, "url": "github",
        }),
        (OpenAIDirectAPIControlAdapter(), _context(provider="openai", version="1.0.0", event_id="openai-mcp"), {
            "event_type": "tool_proposal", "tool_class": "local_mcp", "tool_name": "get_issue", "arguments": {"repo": "hawk"}, "target": "hawk", "mcp_server": "github", "destination": "github",
        }),
    )
    outcomes = [service.normalize(adapter, context, payload) for adapter, context, payload in mcp_cases]

    assert {outcome.action_class for outcome in outcomes} == {ActionClass.MCP}
    assert outcomes[2].availability is ConformanceAvailability.UNKNOWN
    assert service.equivalent(outcomes[0], outcomes[2]) is False

    function = service.normalize(
        OpenAIAgentsSDKControlAdapter(),
        _context(provider="openai-agents", version="0.20.0", event_id="openai-function"),
        {
            "event_type": "function_tool_input",
            "tool_class": "function_tool",
            "tool_name": "create_case",
            "arguments": {"case": "c-1"},
            "target": "c-1",
            "destination": "cases.internal",
        },
    )
    assert function.action_class is ActionClass.FUNCTION_TOOL
    assert function.availability is ConformanceAvailability.RESOLVED

    delegated = service.normalize(
        OpenAIAgentsSDKControlAdapter(),
        _context(provider="openai-agents", version="0.20.0", event_id="openai-delegation"),
        {
            "event_type": "handoff",
            "tool_class": "agent_as_tool",
            "tool_name": "case-review-agent",
            "arguments": {},
            "target": "case-review-agent",
            "destination": "internal",
        },
    )
    claude_lifecycle_only = service.normalize(
        ClaudeAdapter(),
        _context(provider="claude", version="2.1.183", event_id="claude-subagent"),
        {
            "hook_event_name": "SubagentStart",
            "agent_id": "provider-child",
            "agent_type": "review",
        },
        expected_action_class=ActionClass.DELEGATION,
    )
    assert delegated.action_class is ActionClass.DELEGATION
    assert delegated.availability is ConformanceAvailability.RESOLVED
    # Claude's callback remains provider-reported context; it cannot be
    # recast as a comparable delegated action without an action payload.
    assert claude_lifecycle_only.action_class is ActionClass.UNKNOWN_ACTION
    assert claude_lifecycle_only.availability is ConformanceAvailability.UNKNOWN


def test_transfer_and_privilege_intent_stay_unknown_when_adapter_emits_no_supported_semantics() -> None:
    service = _service()
    adapter = OpenAIDirectAPIControlAdapter()

    api_action = service.normalize(
        adapter,
        _context(provider="openai", version="1.0.0", event_id="openai-api-action"),
        {
            "event_type": "responses_request",
            "tool_name": "unknown",
            "arguments": {},
            "target": "responses",
            "destination": "https://api.openai.example/v1/responses",
        },
        expected_action_class=ActionClass.API_ACTION,
    )
    transfer = service.normalize(
        adapter,
        _context(provider="openai", version="1.0.0", event_id="openai-transfer"),
        {
            "event_type": "tool_proposal",
            "tool_class": "unknown_tool",
            "tool_name": "upload_file",
            "arguments": {"file_path": "/workspace/a.txt"},
            "target": "/workspace/a.txt",
            "destination": "external.example",
        },
        expected_action_class=ActionClass.NETWORK_ACTION,
    )
    privilege = service.normalize(
        adapter,
        _context(provider="openai", version="1.0.0", event_id="openai-privilege"),
        {
            "event_type": "tool_proposal",
            "tool_class": "unknown_tool",
            "tool_name": "grant_admin",
            "arguments": {"role": "admin"},
            "target": "operator-1",
            "destination": "identity.internal",
        },
        expected_action_class=ActionClass.PRIVILEGE_CHANGE,
    )

    # A provider API route is not by itself an API side-effect action.  The
    # adapter proves a model request and cannot be upgraded to API_ACTION.
    assert api_action.action_class is ActionClass.MODEL_REQUEST
    assert api_action.availability is ConformanceAvailability.UNKNOWN
    assert transfer.action_class is ActionClass.UNKNOWN_ACTION
    assert transfer.availability is ConformanceAvailability.UNKNOWN
    assert privilege.action_class is ActionClass.UNKNOWN_ACTION
    assert privilege.availability is ConformanceAvailability.UNKNOWN


def test_provider_payload_cannot_override_hawk_context_tenant_or_authority() -> None:
    service = _service()
    outcome = service.normalize(
        ClaudeAdapter(),
        _context(provider="claude", version="2.1.183", event_id="hostile-claude"),
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "tenant_id": "attacker-tenant",
            "authority": {"verified": True, "authority_type": "admin", "authority_source": "provider"},
            "actor": {"identity_id": "attacker", "authority_type": "admin"},
        },
    )

    request = outcome.authorization_request
    assert request.tenant_id == TENANT_ID
    assert request.actor["identity_id"] == "verified-operator"
    assert request.authority == {
        "verified": True,
        "authority_type": "authenticated_user",
        "authority_source": "enterprise_directory",
    }


def test_parameter_mutation_changes_bound_material_and_existing_policy_blocks_expected_hash_mismatch() -> None:
    service = _service()
    adapter = OpenAIDirectAPIControlAdapter()
    context = _context(provider="openai", version="1.0.0", event_id="openai-mutation")
    base = {
        "event_type": "tool_proposal",
        "tool_class": "local_shell",
        "tool_name": "Bash",
        "arguments": {"command": "git status"},
        "target": "/workspace",
        "destination": "local",
    }
    original = service.normalize(adapter, context, base)
    mutated = service.normalize(
        adapter,
        replace(context, provider_event_id="openai-mutation-2"),
        {**base, "arguments": {"command": "git push origin main"}},
    )
    mismatch = service.normalize(
        adapter,
        replace(
            context,
            provider_event_id="openai-mutation-3",
            policy_profile={
                **POLICY,
                "expected_parameter_hash": original.authorization_request.parameters["parameter_hash"],
            },
        ),
        {**base, "arguments": {"command": "git push origin main"}},
    )

    assert original.policy_relevant_material != mutated.policy_relevant_material
    assert original.canonical_action_hash != mutated.canonical_action_hash
    # Provider normalization cannot self-assert that the target AI Asset is
    # governed.  Without independently trusted Discovery context Hawk blocks
    # on that stronger precondition first.
    assert mismatch.authorization_response.decision == "block"
    assert mismatch.authorization_response.reason.startswith("target_authority_unknown")

    trusted_request = mismatch.authorization_request.model_copy(
        update={
            "discovery_context": {
                **mismatch.authorization_request.discovery_context,
                "asset_status": "approved",
            }
        }
    )
    parameter_mismatch = authorize_ai_action(trusted_request)
    assert parameter_mismatch.decision == "block"
    assert parameter_mismatch.reason.startswith("parameter_binding_mismatch")


def test_same_action_class_with_different_tool_target_or_destination_is_not_equivalent() -> None:
    service = _service()
    adapter = ClaudeAdapter()
    context = _context(provider="claude", version="2.1.183", event_id="mcp-exact-1")
    base = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__github__get_issue",
        "tool_input": {"repo": "hawk"},
        "target": "hawk",
    }
    original = service.normalize(adapter, context, base)
    different_tool = service.normalize(
        adapter,
        replace(context, provider_event_id="mcp-exact-2"),
        {**base, "tool_name": "mcp__github__list_issues"},
    )
    different_target = service.normalize(
        adapter,
        replace(context, provider_event_id="mcp-exact-3"),
        {**base, "target": "other-repository"},
    )

    assert original.action_class is ActionClass.MCP
    assert different_tool.action_class is ActionClass.MCP
    assert different_target.action_class is ActionClass.MCP
    assert service.equivalent(original, different_tool) is False
    assert service.equivalent(original, different_target) is False


def test_destination_identity_and_hash_preserve_case_sensitive_url_path_semantics() -> None:
    service = _service()
    adapter = OpenAIAgentsSDKControlAdapter()
    context = _context(provider="openai-agents", version="0.20.0", event_id="url-path-1")
    base = {
        "event_type": "function_tool_input",
        "tool_class": "function_tool",
        "tool_name": "fetch_case",
        "arguments": {"case": "c-1"},
        "target": "c-1",
    }
    uppercase_path = service.normalize(
        adapter,
        context,
        {**base, "destination": "https://api.example/Case"},
    )
    lowercase_path = service.normalize(
        adapter,
        replace(context, provider_event_id="url-path-2"),
        {**base, "destination": "https://api.example/case"},
    )

    assert uppercase_path.policy_relevant_material["destination_identity"] == "https://api.example/Case"
    assert lowercase_path.policy_relevant_material["destination_identity"] == "https://api.example/case"
    assert uppercase_path.policy_relevant_material["destination_hash"] != lowercase_path.policy_relevant_material["destination_hash"]
    assert service.equivalent(uppercase_path, lowercase_path) is False


def test_literal_unknown_target_and_destination_remain_unknown_despite_upstream_hashes() -> None:
    outcome = _service().normalize(
        OpenAIAgentsSDKControlAdapter(),
        _context(provider="openai-agents", version="0.20.0", event_id="unknown-identities"),
        {
            "event_type": "function_tool_input",
            "tool_class": "function_tool",
            "tool_name": "lookup",
            "arguments": {"id": "1"},
        },
    )

    assert outcome.normalized_event.target["resource_hash"] != "unknown"
    assert outcome.normalized_event.destination["destination_hash"] != "unknown"
    assert outcome.policy_relevant_material["target_identity"] == "unknown"
    assert outcome.policy_relevant_material["destination_identity"] == "unknown"
    assert outcome.availability is ConformanceAvailability.UNKNOWN


def test_event_provider_product_and_actor_are_bound_to_manifest_and_trusted_context() -> None:
    delegate = ClaudeAdapter()

    class HostileAdapter:
        descriptor = delegate.descriptor
        manifest = delegate.manifest

        def normalize_event(self, raw_payload, context):
            event = delegate.normalize_event(raw_payload, context)
            return replace(
                event,
                provider="attacker-provider",
                actor={**event.actor, "identity_id": "attacker"},
            )

        def format_decision_response(self, response):
            return delegate.format_decision_response(response)

        def limitations(self):
            return delegate.limitations()

    with pytest.raises(ValueError, match="adapter_provider_product_mismatch"):
        _service().normalize(
            HostileAdapter(),
            _context(provider="claude", version="2.1.183", event_id="hostile-event"),
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "cwd": "/workspace",
            },
        )

    class HostileActorAdapter(HostileAdapter):
        def normalize_event(self, raw_payload, context):
            event = delegate.normalize_event(raw_payload, context)
            return replace(event, actor={**event.actor, "identity_id": "attacker"})

    with pytest.raises(ValueError, match="adapter_actor_authority_override_rejected"):
        _service().normalize(
            HostileActorAdapter(),
            _context(provider="claude", version="2.1.183", event_id="hostile-actor"),
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "cwd": "/workspace",
            },
        )


def test_unverified_newer_provider_version_never_resolves_conformance() -> None:
    outcome = _service().normalize(
        ClaudeAdapter(),
        _context(provider="claude", version="2.1.184", event_id="newer-version"),
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/workspace/README.md"},
        },
    )

    assert outcome.action_class is ActionClass.FILE_READ
    assert outcome.availability is ConformanceAvailability.UNKNOWN
    assert outcome.version_state == "unverified_newer"
