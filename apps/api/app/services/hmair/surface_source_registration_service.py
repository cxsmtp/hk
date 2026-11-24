"""Typed owner-controlled registration for H2 browser and runtime sources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget


_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SOURCE_TYPES: dict[str, tuple[str, str, tuple[str, ...], tuple[str, ...]]] = {
    "managed_browser": (
        "browser_tenant",
        "browser_management",
        ("managed_browser_health",),
        (
            "metadata_only",
            "requires_fresh_managed_extension_health",
            "does_not_collect_prompts_cookies_history_or_page_content",
        ),
    ),
    "mcp_environment": (
        "mcp_environment",
        "runtime_registry",
        ("routed_mcp_events",),
        (
            "metadata_only",
            "requires_fresh_routed_mcp_evidence",
            "does_not_collect_tool_arguments_results_or_credentials",
        ),
    ),
    "llm_gateway": (
        "llm_gateway",
        "runtime_registry",
        ("routed_llm_events",),
        (
            "metadata_only",
            "requires_fresh_routed_llm_evidence",
            "does_not_collect_prompts_tool_output_or_credentials",
        ),
    ),
    "runtime_environment": (
        "runtime_environment",
        "runtime_registry",
        ("routed_runtime_events",),
        (
            "metadata_only",
            "requires_fresh_routed_runtime_evidence",
            "does_not_collect_prompts_tool_arguments_results_or_credentials",
        ),
    ),
}
_SOURCE_KIND = Literal[
    "managed_browser", "mcp_environment", "llm_gateway", "runtime_environment"
]


class ManagedBrowserUnitInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_id: str = Field(min_length=1, max_length=128)
    browser: str = Field(min_length=1, max_length=64)
    browser_profile: str = Field(min_length=1, max_length=128)

    @field_validator("endpoint_id", "browser", "browser_profile")
    @classmethod
    def require_safe_unit_reference(cls, value: str) -> str:
        normalized = value.strip()
        if _SAFE_REFERENCE.fullmatch(normalized) is None:
            raise ValueError("managed browser unit references must be opaque safe identifiers")
        return normalized


class SurfaceSourceRegistrationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: _SOURCE_KIND
    target_identifier: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    expected_count: StrictInt = Field(ge=1, le=10_000_000)
    authority_reference: str = Field(min_length=1, max_length=128)
    baseline_expires_at: datetime
    managed_browser_units: list[ManagedBrowserUnitInput] = Field(
        default_factory=list, max_length=10_000
    )

    @field_validator("target_identifier", "environment", "authority_reference")
    @classmethod
    def require_safe_reference(cls, value: str) -> str:
        normalized = value.strip()
        if _SAFE_REFERENCE.fullmatch(normalized) is None:
            raise ValueError("surface source references must be opaque safe identifiers")
        return normalized

    @field_validator("baseline_expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("surface source baseline expiry must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_managed_units(self) -> "SurfaceSourceRegistrationInput":
        if self.source_kind != "managed_browser" and self.managed_browser_units:
            raise ValueError("managed browser units apply only to managed_browser sources")
        if self.managed_browser_units and len(self.managed_browser_units) != self.expected_count:
            raise ValueError("managed browser unit count must match expected_count")
        return self


@dataclass(frozen=True, slots=True)
class SurfaceSourceRegistrationRecord:
    target: DiscoveryTarget
    collector: DiscoveryCollector
    created: bool


def _now(value: datetime | None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("surface source registration time must include a timezone")
    return observed.astimezone(UTC)


def _binding_digest(*, tenant_id: str, target_type: str, identifier: str) -> str:
    return sha256(f"{tenant_id}\x00{target_type}\x00{identifier}".encode("utf-8")).hexdigest()


def _declaration_hash(
    *, collector_id: str, target_type: str, permissions: tuple[str, ...], limitations: tuple[str, ...]
) -> str:
    material = {
        "collector_id": collector_id,
        "collector_type": "hmair_h2_surface_bridge",
        "version": "v1",
        "supported_targets": [target_type],
        "permissions": list(permissions),
        "limitations": list(limitations),
    }
    return sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _authorization_reference(value: str) -> str:
    return "authorization:" + sha256(value.encode("utf-8")).hexdigest()[:48]


def register_surface_source(
    db: Session,
    *,
    tenant_id: str,
    input: SurfaceSourceRegistrationInput,
    now: datetime | None = None,
) -> SurfaceSourceRegistrationRecord:
    """Register an authorized metadata source without claiming it is connected."""

    if type(input) is not SurfaceSourceRegistrationInput:
        raise TypeError("surface source registration input is invalid")
    observed_now = _now(now)
    if input.baseline_expires_at <= observed_now:
        raise ValueError("surface source baseline is already expired")

    target_type, authority_kind, permissions, limitations = _SOURCE_TYPES[input.source_kind]
    if target_type == "browser_tenant":
        other_browser = db.scalar(
            select(DiscoveryTarget).where(
                DiscoveryTarget.tenant_id == tenant_id,
                DiscoveryTarget.target_type == "browser_tenant",
            )
        )
        if other_browser is not None and other_browser.identifier != input.target_identifier:
            raise ValueError("only one managed browser source may be registered per tenant")

    binding = _binding_digest(
        tenant_id=tenant_id,
        target_type=target_type,
        identifier=input.target_identifier,
    )
    target_id = f"hmair-surface-target-{binding[:40]}"
    collector_id = f"hmair-surface-collector-{binding[:40]}"
    baseline = {
        "expected_count": input.expected_count,
        "authority_kind": authority_kind,
        "authority_reference": input.authority_reference,
        "verified_at": observed_now.isoformat(),
        "expires_at": input.baseline_expires_at.isoformat(),
    }
    if target_type == "browser_tenant":
        from app.services.hmair.deep_scan_source_service import (
            managed_browser_unit_binding_hash,
        )

        baseline["managed_browser_unit_hashes"] = sorted(
            {
                managed_browser_unit_binding_hash(
                    endpoint_id=unit.endpoint_id,
                    browser=unit.browser,
                    browser_profile=unit.browser_profile,
                )
                for unit in input.managed_browser_units
            }
        )
    target = db.scalar(
        select(DiscoveryTarget).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.target_id == target_id,
        )
    )
    created = target is None
    if target is None:
        target = DiscoveryTarget(
            target_id=target_id,
            tenant_id=tenant_id,
            target_type=target_type,
            identifier=input.target_identifier,
            environment=input.environment,
            owner_hint="customer_source_admin",
            credentials_reference=_authorization_reference(input.authority_reference),
            permitted_methods_json=["collect_inventory"],
            exclusions_json=[
                "raw_content",
                "prompt_content",
                "cookies",
                "tool_arguments",
                "tool_results",
                "credentials",
            ],
            rate_limit=1_000,
            active_scan_allowed=True,
            sensitive_scope=False,
            coverage_baseline_json=baseline,
        )
        db.add(target)
    else:
        if target.target_type != target_type or target.identifier != input.target_identifier:
            raise ValueError("surface source target configuration conflict")
        target.environment = input.environment
        target.owner_hint = "customer_source_admin"
        target.credentials_reference = _authorization_reference(input.authority_reference)
        target.permitted_methods_json = ["collect_inventory"]
        target.exclusions_json = [
            "raw_content",
            "prompt_content",
            "cookies",
            "tool_arguments",
            "tool_results",
            "credentials",
        ]
        target.rate_limit = 1_000
        target.active_scan_allowed = True
        target.sensitive_scope = False
        target.coverage_baseline_json = baseline

    collector = db.scalar(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == collector_id,
        )
    )
    declaration_hash = _declaration_hash(
        collector_id=collector_id,
        target_type=target_type,
        permissions=permissions,
        limitations=limitations,
    )
    if collector is None:
        collector = DiscoveryCollector(
            collector_id=collector_id,
            tenant_id=tenant_id,
            collector_type="hmair_h2_surface_bridge",
            version="v1",
            supported_targets_json=[target_type],
            active_capabilities_json=[],
            passive_capabilities_json=["metadata_only"],
            permissions_required_json=list(permissions),
            sensitive_data_accessed_json=[],
            health="unknown",
            last_success_at=None,
            last_failure_at=None,
            data_residency="tenant-selected",
            control_capability="monitor_only",
            schema_version="v1",
            limitations_json=list(limitations),
            declaration_hash=declaration_hash,
        )
        db.add(collector)
    elif (
        collector.collector_type != "hmair_h2_surface_bridge"
        or collector.supported_targets_json != [target_type]
    ):
        raise ValueError("surface source collector configuration conflict")
    else:
        collector.version = "v1"
        collector.active_capabilities_json = []
        collector.passive_capabilities_json = ["metadata_only"]
        collector.permissions_required_json = list(permissions)
        collector.sensitive_data_accessed_json = []
        collector.data_residency = "tenant-selected"
        collector.control_capability = "monitor_only"
        collector.schema_version = "v1"
        collector.limitations_json = list(limitations)
        collector.declaration_hash = declaration_hash
    db.flush()
    return SurfaceSourceRegistrationRecord(
        target=target, collector=collector, created=created
    )


__all__ = [
    "SurfaceSourceRegistrationInput",
    "SurfaceSourceRegistrationRecord",
    "register_surface_source",
]
