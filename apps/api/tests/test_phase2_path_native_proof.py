from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.hmair.collector_registry import CollectorRegistry
from app.services.hmair.collectors.browser import BrowserPathCollector
from app.services.hmair.collectors.endpoint import EndpointPathCollector
from app.services.hmair.collectors.llm_gateway import LLMGatewayPathCollector
from app.services.hmair.collectors.mcp_gateway import MCPGatewayPathCollector
from app.services.hmair.collectors.path_native import (
    PathNativeSignal,
    register_path_native_collectors,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _signal(**updates: object) -> PathNativeSignal:
    values: dict[str, object] = {
        "observation_id": "path-observation-a",
        "scan_id": "00000000-0000-0000-0000-000000000001",
        "target_id": "managed-surface-a",
        "subject_reference": "subject:fingerprint-a",
        "raw_signal_type": "running_process",
        "asset_candidate_type": "unknown_ai_candidate",
        "observed_state": "observed",
        "normalized_signal": {"process_family": "unknown_local_inference"},
        "identifiers": {"device_ref": "device:fingerprint-a"},
        "configuration_summary": {},
        "usage_summary": {},
        "capability_hints": ("inference",),
        "identity_hints": (),
        "relationship_hints": (),
        "evidence_reference": "evidence://path-native-a",
        "evidence_hash": "a" * 64,
        "observed_at": NOW,
        "confidence": 0.65,
        "freshness": "fresh",
        "verification_state": "partially_verified",
        "source_trust": "medium",
        "collection_scope": {"scope_type": "managed_endpoint"},
        "evidence_mode": "direct",
        "evidence_mutability": "immutable",
        "contradiction_state": "none",
        "contradiction_references": (),
    }
    values.update(updates)
    return PathNativeSignal(**values)


def test_path_native_collectors_keep_installed_usage_and_bypass_truth_separate() -> None:
    endpoint = EndpointPathCollector(
        signals=(
            _signal(observed_state="installed", raw_signal_type="installed_application"),
        )
    )
    browser = BrowserPathCollector(
        signals=(
            _signal(
                observation_id="path-browser-a",
                raw_signal_type="web_ai_usage",
                asset_candidate_type="ai_saas",
                observed_state="actively_used",
                normalized_signal={"product_family": "enterprise_ai_web"},
                usage_summary={"event_count": 1, "actor_class": "human"},
                source_trust="strong",
                verification_state="verified",
                confidence=0.95,
            ),
        )
    )
    mcp = MCPGatewayPathCollector(
        signals=(
            _signal(
                observation_id="path-mcp-a",
                raw_signal_type="mcp_tool",
                asset_candidate_type="mcp_tool",
                observed_state="observed",
                normalized_signal={"tool_schema_fingerprint": "b" * 64},
                relationship_hints=({"relationship": "exposes"},),
            ),
        )
    )
    llm = LLMGatewayPathCollector(
        signals=(
            _signal(
                observation_id="path-llm-a",
                raw_signal_type="api_call",
                asset_candidate_type="model_endpoint",
                observed_state="actively_used",
                normalized_signal={"route_class": "direct_provider_bypass"},
                relationship_hints=({"relationship": "connects_to"},),
                usage_summary={"request_count": 1, "actor_class": "workload"},
            ),
        )
    )

    endpoint_observation = endpoint.emit_observations()[0]
    browser_observation = browser.emit_observations()[0]
    assert endpoint_observation.observed_state.value == "installed"
    assert dict(endpoint_observation.usage_summary) == {}
    assert browser_observation.observed_state.value == "actively_used"
    assert mcp.emit_observations()[0].source_surface.value == "mcp"
    assert dict(llm.emit_observations()[0].normalized_signal)["route_class"] == "direct_provider_bypass"


def test_path_native_registration_is_explicit_and_default_off() -> None:
    registry = CollectorRegistry()
    register_path_native_collectors(registry, enabled=False)
    assert registry.list_declarations() == ()
    register_path_native_collectors(registry, enabled=True)
    assert {item.collector_type for item in registry.list_declarations()} == {
        "phase2_browser",
        "phase2_endpoint",
        "phase2_llm_gateway",
        "phase2_mcp_gateway",
    }


def test_path_native_signal_rejects_private_material() -> None:
    with pytest.raises(ValueError):
        _signal(normalized_signal={"api_token": "must-not-enter-discovery"})
    with pytest.raises(ValueError):
        _signal(usage_summary={"prompt": "raw prompt body"})
    with pytest.raises(ValueError):
        _signal(configuration_summary={"source_code": "print('private')"})

