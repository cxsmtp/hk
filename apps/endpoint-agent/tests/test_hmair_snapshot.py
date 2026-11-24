from __future__ import annotations

from datetime import datetime, timezone
import json

import hawk_endpoint_agent.__main__ as agent_cli
import pytest

try:
    from hawk_endpoint_agent.hmair_snapshot import (
        HMAIRSnapshotError,
        build_hmair_snapshot_payload,
        run_hmair_discovery_snapshot,
    )
except ImportError:  # TDD: assertions below are the expected red state.
    HMAIRSnapshotError = ValueError
    build_hmair_snapshot_payload = None
    run_hmair_discovery_snapshot = None

from hawk_endpoint_agent.config import AgentConfig


def _metadata_report() -> dict[str, object]:
    return {
        "schema_version": "hawk.endpoint_metadata.v1",
        "status": "completed",
        "collection_mode": "one_shot_read_only",
        "network_used": False,
        "products": [
            {
                "id": "codex_cli",
                "name": "Codex CLI",
                "provider": "openai",
                "category": "cli",
                "presence": "present",
                "version": "1.2.3",
                "evidence_types": ["configuration"],
                "approval_status": "unknown",
                "account": {
                    "status": "unknown",
                    "identifiers_collected": False,
                    "email": "must-not-copy@example.test",
                },
                "prompt_history": ["must not upload"],
            }
        ],
        "extensions": [],
        "configurations": [
            {
                "product_id": "codex_cli",
                "kind": "mcp_agent_configuration",
                "source": "codex_config",
                "status": "present",
                "metadata": {
                    "model": "gpt-5-codex",
                    "model_provider": "openai",
                    "mcp_server_names": ["filesystem"],
                    "api_key": "must-not-copy",
                    "prompt": "must-not-copy",
                },
            }
        ],
        "errors": [],
        "privacy": {
            "raw_file_contents_collected": False,
            "prompts_collected": False,
            "browser_history_collected": False,
            "cookies_collected": False,
            "secrets_or_tokens_collected": False,
            "account_identifiers_collected": False,
            "persistent_state_written": False,
        },
    }


def test_builds_a_strict_metadata_only_hmair_snapshot() -> None:
    assert build_hmair_snapshot_payload is not None
    payload = build_hmair_snapshot_payload(
        _metadata_report(),
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )

    assert payload["snapshot_id"] == "lab-snapshot-001"
    assert payload["products"][0]["account"] == {
        "status": "unknown",
        "identifiers_collected": False,
    }
    assert payload["configurations"][0]["metadata"] == {
        "model": "gpt-5-codex",
        "model_provider": "openai",
        "mcp_server_names": ["filesystem"],
    }
    serialized = json.dumps(payload, sort_keys=True)
    for forbidden in (
        "must-not-copy@example.test",
        "must not upload",
        "must-not-copy",
    ):
        assert forbidden not in serialized


def test_snapshot_payload_preserves_only_a_safe_inventory_assignment_id() -> None:
    assert build_hmair_snapshot_payload is not None

    payload = build_hmair_snapshot_payload(
        _metadata_report(),
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
        inventory_assignment_id="e08d8ca9-b31c-4fe6-b559-b9ca57bf2e06",
    )

    assert payload["inventory_assignment_id"] == "e08d8ca9-b31c-4fe6-b559-b9ca57bf2e06"


def test_normalizes_a_privacy_ambiguous_extension_version() -> None:
    assert build_hmair_snapshot_payload is not None
    report = _metadata_report()
    report["extensions"] = [
        {
            "id": "example.extension",
            "name": "Example Extension",
            "provider": "example",
            "host": "browser",
            "category": "browser",
            "presence": "present",
            "version": "202409041234",
            "approval_status": "unknown",
        }
    ]

    payload = build_hmair_snapshot_payload(
        report,
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
    )

    assert payload["extensions"][0]["version"] == "unknown"


def test_preserves_a_dotted_semantic_extension_version() -> None:
    """A normal application version is inventory metadata, not a phone number."""

    assert build_hmair_snapshot_payload is not None
    report = _metadata_report()
    report["extensions"] = [
        {
            "id": "chatgpt.extension",
            "name": "ChatGPT",
            "provider": "openai",
            "host": "chrome",
            "category": "browser",
            "presence": "present",
            "version": "1.26.901.11451",
            "approval_status": "unknown",
        }
    ]

    payload = build_hmair_snapshot_payload(
        report,
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
    )

    assert payload["extensions"][0]["version"] == "1.26.901.11451"


def test_redacts_a_dotted_telephone_shaped_extension_version() -> None:
    assert build_hmair_snapshot_payload is not None
    report = _metadata_report()
    report["extensions"] = [
        {
            "id": "example.extension",
            "name": "Example Extension",
            "provider": "example",
            "host": "browser",
            "category": "browser",
            "presence": "present",
            "version": "971.50.123.4567",
            "approval_status": "unknown",
        }
    ]

    payload = build_hmair_snapshot_payload(
        report,
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
    )

    assert payload["extensions"][0]["version"] == "unknown"


def test_collapses_duplicate_extension_identity_with_an_uncertain_version() -> None:
    assert build_hmair_snapshot_payload is not None
    report = _metadata_report()
    report["extensions"] = [
        {
            "id": "example.extension",
            "name": "Example Extension",
            "provider": "example",
            "host": "browser",
            "category": "browser",
            "presence": "present",
            "version": "1.2.3",
            "approval_status": "unknown",
        },
        {
            "id": "example.extension",
            "name": "Example Extension",
            "provider": "example",
            "host": "browser",
            "category": "browser",
            "presence": "present",
            "version": "1.2.4",
            "approval_status": "unknown",
        },
    ]

    payload = build_hmair_snapshot_payload(
        report,
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
    )

    assert payload["extensions"] == [
        {
            "id": "example.extension",
            "name": "Example Extension",
            "provider": "example",
            "host": "browser",
            "category": "browser",
            "presence": "present",
            "version": "unknown",
            "approval_status": "unknown",
        }
    ]


@pytest.mark.parametrize("assignment_id", ("not-a-uuid", "", "../escape"))
def test_snapshot_payload_rejects_an_invalid_inventory_assignment_id(
    assignment_id: str,
) -> None:
    assert build_hmair_snapshot_payload is not None

    with pytest.raises(HMAIRSnapshotError):
        build_hmair_snapshot_payload(
            _metadata_report(),
            snapshot_id="lab-snapshot-001",
            collected_at=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
            inventory_assignment_id=assignment_id,
        )


def test_runs_one_explicit_snapshot_and_returns_only_the_server_receipt() -> None:
    assert run_hmair_discovery_snapshot is not None
    captured: dict[str, object] = {}

    class _Client:
        def report_hmair_snapshot(self, payload: dict[str, object]) -> dict[str, object]:
            captured["payload"] = payload
            return {
                "scan_id": "00000000-0000-4000-8000-000000000001",
                "status": "complete",
                "observations_count": 2,
                "endpoint_denominator": 1,
                "limitations": ["coverage:single_enrolled_endpoint"],
                "ignored": "never return raw scan details",
            }

    receipt = run_hmair_discovery_snapshot(
        AgentConfig(tenant_id="tenant-1", endpoint_id="endpoint-1"),
        client=_Client(),
        scanner=_metadata_report,
        snapshot_id="lab-snapshot-001",
        collected_at=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )

    assert captured["payload"]["snapshot_id"] == "lab-snapshot-001"
    assert receipt == {
        "scan_id": "00000000-0000-4000-8000-000000000001",
        "status": "complete",
        "observations_count": 2,
        "endpoint_denominator": 1,
        "limitations": ["coverage:single_enrolled_endpoint"],
    }


def test_rejects_an_invalid_snapshot_receipt_before_it_reaches_cli_output() -> None:
    class _InvalidClient:
        def report_hmair_snapshot(self, _payload: dict[str, object]) -> dict[str, object]:
            return {
                "scan_id": "00000000-0000-4000-8000-000000000001",
                "status": "complete",
                "observations_count": True,
                "endpoint_denominator": 1,
                "limitations": ["coverage:single_enrolled_endpoint"],
            }

    with pytest.raises(HMAIRSnapshotError):
        run_hmair_discovery_snapshot(
            AgentConfig(tenant_id="tenant-1", endpoint_id="endpoint-1"),
            client=_InvalidClient(),
            scanner=_metadata_report,
            snapshot_id="lab-snapshot-001",
            collected_at=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
        )


def test_agent_cli_runs_a_snapshot_only_with_the_explicit_flag(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def _run(config: AgentConfig) -> dict[str, object]:
        captured["config"] = config
        return {
            "scan_id": "00000000-0000-4000-8000-000000000001",
            "status": "complete",
            "observations_count": 2,
            "endpoint_denominator": 1,
            "limitations": ["coverage:single_enrolled_endpoint"],
        }

    config = AgentConfig(tenant_id="tenant-1", endpoint_id="endpoint-1")
    monkeypatch.setattr(agent_cli, "load_config", lambda _path: config)
    monkeypatch.setattr(
        agent_cli,
        "run_hmair_discovery_snapshot",
        _run,
        raising=False,
    )

    result = agent_cli.main(
        ["--config", "/private/lab-endpoint.json", "--hmair-discovery-snapshot"]
    )

    assert result == 0
    assert captured["config"] is config
    assert json.loads(capsys.readouterr().out) == {
        "endpoint_denominator": 1,
        "limitations": ["coverage:single_enrolled_endpoint"],
        "observations_count": 2,
        "ok": True,
        "scan_id": "00000000-0000-4000-8000-000000000001",
        "status": "complete",
    }
