from __future__ import annotations

from dataclasses import dataclass
import json

from app.services.native_control.providers import canonical_provider


@dataclass(frozen=True, slots=True)
class ConfiguredRouteBinding:
    source: str
    integration_instance_ids: tuple[str, ...]
    provider: str
    provider_version: str
    adapter_version: str
    product: str
    allowed_methods: tuple[str, ...]


_SURFACE_RULES = {
    "llm_gateway": ("hawk_gateway_route", ("gateway_inline",)),
    "mcp_gateway": ("hawk_gateway_route", ("gateway_inline",)),
    # The in-process MCP registry is also a Hawk-owned inline route.  It still
    # requires an explicitly configured, accepted tenant control point; this
    # entry only makes that route representable to the shared selector.
    "internal_mcp": ("hawk_runtime_route", ("gateway_inline",)),
    "runtime_control": ("hawk_runtime_route", ("endpoint_runtime", "native_hook")),
}


def configured_route_bindings(
    settings_obj: object,
    surface: str,
    *,
    tenant_id: str,
) -> tuple[ConfiguredRouteBinding, ...]:
    normalized_surface = str(surface or "").strip().lower()
    rule = _SURFACE_RULES.get(normalized_surface)
    if rule is None or not tenant_id:
        return ()
    try:
        bindings = json.loads(
            str(getattr(settings_obj, "native_control_route_bindings_json", "{}") or "{}")
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        return ()
    tenant_bindings = bindings.get(tenant_id) if isinstance(bindings, dict) else None
    configured = tenant_bindings.get(normalized_surface) if isinstance(tenant_bindings, dict) else None
    raw_bindings = configured if isinstance(configured, list) else [configured]
    source, allowed_methods = rule
    parsed: list[ConfiguredRouteBinding] = []
    for item in raw_bindings:
        if not isinstance(item, dict) or set(item) != {
            "integration_instance_ids",
            "provider",
            "provider_version",
            "adapter_version",
            "product",
        }:
            return ()
        raw_ids = item.get("integration_instance_ids")
        if not isinstance(raw_ids, list):
            return ()
        ids = tuple(
            dict.fromkeys(
                str(token or "").strip()
                for token in raw_ids
                if str(token or "").strip()
            )
        )
        provider = canonical_provider(str(item.get("provider") or ""))
        provider_version = str(item.get("provider_version") or "").strip()
        adapter_version = str(item.get("adapter_version") or "").strip()
        product = str(item.get("product") or "").strip().lower()
        if not ids or len(ids) > 8 or any(len(token) > 64 for token in ids):
            return ()
        if provider == "unknown" or not provider_version or not adapter_version or not product:
            return ()
        parsed.append(
            ConfiguredRouteBinding(
                source=source,
                integration_instance_ids=ids,
                provider=provider,
                provider_version=provider_version,
                adapter_version=adapter_version,
                product=product,
                allowed_methods=allowed_methods,
            )
        )
    if len({binding.provider for binding in parsed}) != len(parsed):
        return ()
    return tuple(sorted(parsed, key=lambda binding: binding.provider))


def configured_route_binding(
    settings_obj: object,
    surface: str,
    *,
    tenant_id: str,
    provider: str | None = None,
) -> ConfiguredRouteBinding | None:
    bindings = configured_route_bindings(settings_obj, surface, tenant_id=tenant_id)
    if provider is not None:
        expected = canonical_provider(provider)
        bindings = tuple(binding for binding in bindings if binding.provider == expected)
    return bindings[0] if len(bindings) == 1 else None


def configured_surfaces_for_integration(
    settings_obj: object,
    tenant_id: str,
    integration_id: str,
    integration_method: str,
) -> tuple[str, ...]:
    return tuple(
        surface
        for surface in sorted(_SURFACE_RULES)
        if any(
            integration_id in binding.integration_instance_ids
            and integration_method in binding.allowed_methods
            for binding in configured_route_bindings(
                settings_obj, surface, tenant_id=tenant_id
            )
        )
    )


def current_route_surfaces_for_integration(
    settings_obj: object,
    *,
    tenant_id: str,
    integration_id: str,
    integration_method: str,
    provider: str,
    provider_version: str,
    adapter_version: str,
    product: str,
) -> tuple[str, ...]:
    """Return only routes whose complete trusted binding still matches the integration."""

    expected_provider = canonical_provider(provider)
    expected_product = str(product or "").strip().lower()
    return tuple(
        surface
        for surface in configured_surfaces_for_integration(
            settings_obj,
            tenant_id,
            integration_id,
            integration_method,
        )
        if any(
            binding.provider == expected_provider
            and integration_id in binding.integration_instance_ids
            and integration_method in binding.allowed_methods
            and binding.provider_version == provider_version
            and binding.adapter_version == adapter_version
            and binding.product == expected_product
            for binding in configured_route_bindings(
                settings_obj, surface, tenant_id=tenant_id
            )
        )
    )


def kernel_enforcement_active_for_surfaces(
    settings_obj: object,
    *,
    tenant_id: str,
    surfaces: tuple[str, ...],
) -> bool:
    """Match the server-side Authorization Kernel gate used by live wrappers."""

    if not bool(getattr(settings_obj, "authorization_kernel_v2_enabled", False)):
        return False
    from app.core.control_engine.authorization import is_enforcement_selected

    return any(
        is_enforcement_selected(
            tenant_id=tenant_id,
            surface=surface,
            settings_obj=settings_obj,
        )
        for surface in surfaces
    )
