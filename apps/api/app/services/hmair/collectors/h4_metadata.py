"""Canonical metadata-only adapter for the closed HMAIR H4 catalog."""

from __future__ import annotations

from hashlib import sha256

from app.services.hmair.collectors.h4_catalog import (
    H4CollectorProfile,
    get_h4_collector_profile,
)
from app.services.hmair.collectors.path_native import PathNativeCollector, PathNativeSignal
from app.services.hmair.contracts import canonical_json_bytes


class H4MetadataCollector(PathNativeCollector):
    def __init__(
        self,
        *,
        profile: H4CollectorProfile,
        signals: tuple[PathNativeSignal, ...] = (),
    ) -> None:
        if type(profile) is not H4CollectorProfile:
            raise TypeError("H4 collector profile must be an exact catalog profile")
        if get_h4_collector_profile(profile.profile_id) != profile:
            raise ValueError("H4 collector profile differs from the closed catalog")
        for signal in signals:
            scope = signal.collection_scope
            if scope.get("profile_id") != profile.profile_id:
                raise ValueError("H4 signal does not match collector profile")
            if scope.get("connection_mode") not in profile.supported_connection_modes:
                raise ValueError("H4 signal connection mode is not approved by profile")
            if scope.get("target_type") != profile.target_type.value:
                raise ValueError("H4 signal target does not match collector profile")
            if scope.get("source_surface") != profile.source_surface.value:
                raise ValueError("H4 signal surface does not match collector profile")
            if signal.raw_signal_type not in profile.observation_types:
                raise ValueError("H4 signal type is not approved by profile")
        self.profile = profile
        self.collector_type = f"hmair_h4_{profile.profile_id}"
        self.collector_id = f"hmair-h4-{profile.profile_id}"
        self.source_surface = profile.source_surface
        self.supported_target = profile.target_type
        self.passive_capabilities = profile.passive_capabilities
        self.permissions_required = profile.permissions_required
        self.limitations = profile.limitations
        super().__init__(signals=signals)
        declaration = self.declaration.model_dump(mode="json")
        declaration.update(
            {
                "data_residency": profile.data_residency,
                "control_capability": profile.control_capability,
                "active_capabilities": profile.active_capabilities,
                "sensitive_data_accessed": profile.sensitive_data_accessed,
                "schema_version": "h4.1",
            }
        )
        declaration.pop("declaration_hash")
        declaration["declaration_hash"] = sha256(
            canonical_json_bytes(declaration)
        ).hexdigest()
        self.declaration = self.declaration.model_validate(declaration)


__all__ = ["H4MetadataCollector"]
