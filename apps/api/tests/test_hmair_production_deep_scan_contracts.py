from __future__ import annotations

import pytest

from app.services.hmair.deep_scan_contracts import (
    DeepScanLaunchRequest,
    DeepScanPreflightRequest,
    DeepScanProfile,
    parse_persisted_deep_scan_profile,
    persist_deep_scan_profile,
)


def test_deep_scan_contract_rejects_unbounded_or_content_bearing_scope() -> None:
    with pytest.raises(ValueError):
        DeepScanPreflightRequest.model_validate(
            {
                "target_ids": ["target-browser"],
                "collector_ids": ["collector-browser"],
                "required_target_ids": ["target-browser"],
                "time_window_minutes": 0,
                "customer_authorization_reference": "approval-2026-09",
            }
        )
    with pytest.raises(ValueError):
        DeepScanProfile.model_validate(
            {
                "version": "v1",
                "sources": [],
                "raw_prompt": "must never be accepted",
            }
        )


def test_launch_requires_the_exact_preflight_digest() -> None:
    request = DeepScanLaunchRequest.model_validate(
        {
            "name": "Production AI estate scan",
            "preflight": {
                "target_ids": ["target-browser"],
                "collector_ids": ["collector-browser"],
                "required_target_ids": ["target-browser"],
                "time_window_minutes": 30,
                "customer_authorization_reference": "approval-2026-09",
            },
            "preflight_digest": "a" * 64,
            "dry_run": False,
        }
    )

    assert request.preflight_digest == "a" * 64


def test_full_enterprise_request_requires_every_selected_target() -> None:
    with pytest.raises(ValueError):
        DeepScanPreflightRequest.model_validate(
            {
                "target_ids": ["endpoint-target", "browser-target"],
                "collector_ids": ["endpoint-collector", "browser-collector"],
                "required_target_ids": ["endpoint-target"],
                "time_window_minutes": 30,
                "customer_authorization_reference": "approval-2026-09",
                "requested_mode": "full_enterprise",
            }
        )


def test_persisted_profile_keeps_only_a_one_way_approval_binding() -> None:
    profile = DeepScanProfile.model_validate(
        {
            "version": "v1",
            "mode": "partial",
            "sources": [
                {
                    "target_id": "endpoint-estate",
                    "collector_id": "endpoint-metadata",
                    "target_type": "endpoint_group",
                    "required": True,
                    "state": "ready",
                    "observation_mode": "authoritative",
                    "expected_count": 1,
                    "baseline": {
                        "expected_count": 1,
                        "authority_kind": "mdm",
                        "authority_reference": "mdm-estate",
                        "verified_at": "2026-09-03T00:00:00+00:00",
                        "expires_at": "2026-09-04T00:00:00+00:00",
                    },
                }
            ],
            "customer_authorization_reference": "approval-2026-09",
            "window_start": "2026-09-03T00:00:00+00:00",
            "window_end": "2026-09-03T00:30:00+00:00",
            "issued_at": "2026-09-03T00:00:00+00:00",
            "expires_at": "2026-09-03T00:05:00+00:00",
            "digest": "a" * 64,
        }
    )

    stored = persist_deep_scan_profile(profile)
    material = stored.model_dump(mode="json")

    assert "customer_authorization_reference" not in material
    assert stored.customer_approval_binding_hash != profile.customer_authorization_reference
    assert parse_persisted_deep_scan_profile(material) == stored
    with pytest.raises(ValueError):
        parse_persisted_deep_scan_profile({**material, "storage_digest": "0" * 64})
