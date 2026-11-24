from __future__ import annotations

import hashlib
import json


def configuration_fingerprint(
    *,
    tenant_id: str,
    provider: str,
    product: str,
    method: str,
    instance_key: str,
    environment: str,
    provider_version: str | None,
    adapter_version: str,
    policy_version: str | None,
    runtime: str | None = None,
    model_provider: str | None = None,
    model: str | None = None,
    execution_location: str | None = None,
    deployment_reference: str | None = None,
    trusted_workload_authority: bool = False,
) -> str:
    payload = {
        "tenant_id": tenant_id,
        "provider": provider,
        "product": product,
        "method": method,
        "instance_key": instance_key,
        "environment": environment,
        "provider_version": provider_version,
        "adapter_version": adapter_version,
        "policy_version": policy_version,
        # These are server-managed deployment facts.  Binding them into the
        # configuration fingerprint prevents a local/API configuration change
        # from silently moving a real acceptance onto another runtime.
        "runtime": runtime,
        "model_provider": model_provider,
        "model": model,
        "execution_location": execution_location,
        "deployment_reference": deployment_reference,
        "trusted_workload_authority": bool(trusted_workload_authority),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def integration_configuration_fingerprint(integration: object) -> str:
    return configuration_fingerprint(
        tenant_id=str(getattr(integration, "tenant_id", "")),
        provider=str(getattr(integration, "provider", "")),
        product=str(getattr(integration, "product", "")),
        method=str(getattr(integration, "integration_method", "")),
        instance_key=str(getattr(integration, "instance_key", "")),
        environment=str(getattr(integration, "environment", "")),
        provider_version=getattr(integration, "provider_version", None),
        adapter_version=str(getattr(integration, "adapter_version", "")),
        policy_version=getattr(integration, "policy_version", None),
        runtime=str(getattr(integration, "runtime", "unknown")),
        model_provider=str(getattr(integration, "model_provider", "unknown")),
        model=str(getattr(integration, "model", "unknown")),
        execution_location=str(getattr(integration, "execution_location", "UNKNOWN")),
        deployment_reference=str(getattr(integration, "deployment_reference", "unknown")),
        trusted_workload_authority=bool(
            ((getattr(integration, "capability_snapshot", {}) or {}).get("native_policy") or {})
            .get("trusted_workload_authority") is True
        ),
    )
