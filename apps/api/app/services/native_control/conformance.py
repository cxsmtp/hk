from __future__ import annotations

from dataclasses import dataclass

from app.core.control_engine.authorization import authorize_ai_action
from app.services.native_control.adapter_contract import (
    AdapterContractError,
    AdapterPipelineContext,
    AdapterValidationSuite,
    InstallableControlAdapter,
    NativeControlAdapter,
    SynchronousBlockingAdapter,
    validate_adapter_contract,
)


@dataclass(frozen=True, slots=True)
class AdapterConformanceResult:
    adapter_id: str
    passed: bool
    checks: tuple[str, ...]
    failures: tuple[str, ...]
    exemptions: tuple[str, ...]


class NativeControlAdapterConformanceSuite:
    """Mandatory provider-neutral checks used by future adapter CI."""

    _FORBIDDEN_EXECUTION_METHODS = (
        "remote_shell",
        "execute_command",
        "download_and_execute",
        "load_plugin_from_url",
        "eval",
        "open_listener",
    )

    def run(self, adapter: NativeControlAdapter) -> AdapterConformanceResult:
        adapter_id = str(getattr(getattr(adapter, "descriptor", None), "adapter_id", "unknown"))
        checks: list[str] = []
        failures: list[str] = []

        def check(name: str, operation) -> None:
            try:
                result = operation()
                if result is False:
                    failures.append(f"{name}:failed")
                else:
                    checks.append(name)
            except Exception as exc:
                failures.append(f"{name}:{exc}")

        check("descriptor_manifest_contract", lambda: validate_adapter_contract(adapter))
        if failures:
            return AdapterConformanceResult(
                adapter_id=adapter_id,
                passed=False,
                checks=tuple(checks),
                failures=tuple(failures),
                exemptions=(),
            )

        context = AdapterPipelineContext.reference(
            tenant_id="conformance-tenant",
            integration_instance_id="conformance-integration",
            provider_event_id="conformance-event",
        )
        payload = {
            "tenant_id": "hostile-provider-tenant",
            "event_type": "tool_call",
            "tool_name": "reference.read",
            "parameters": {"id": "bounded"},
            "target": "reference/resource",
        }
        normalized_holder: dict[str, object] = {}

        def normalize() -> bool:
            event = adapter.normalize_event(payload, context)
            normalized_holder["event"] = event
            return (
                event.tenant_id == context.tenant_id
                and event.integration_instance_id == context.integration_instance_id
                and event.provider_event_id == context.provider_event_id
            )

        check("tenant_integration_event_binding", normalize)
        check(
            "raw_payload_boundary",
            lambda: "hostile-provider-tenant" not in str(normalized_holder.get("event")),
        )
        probe_version = (
            adapter.manifest.exact_verified_versions[0]
            if adapter.manifest.exact_verified_versions
            else adapter.manifest.provider_version_min
        )
        report = AdapterValidationSuite().run(adapter, provider_version=probe_version)
        if report.passed:
            checks.append("safe_validation_suite")
        else:
            failures.extend(f"validation:{row.name}" for row in report.tests if not row.passed)

        request = normalized_holder["event"].to_authorization_request()
        block_request = request.model_copy(
            update={
                "policy_profile": {
                    **dict(request.policy_profile),
                    "base_decision": "block",
                    "dependencies_healthy": True,
                }
            }
        )
        block_response = authorize_ai_action(block_request)
        if isinstance(adapter, SynchronousBlockingAdapter):
            check(
                "block_translation_non_weakening",
                lambda: adapter.format_decision_response(block_response).get("continue") is False,
            )
        else:
            try:
                adapter.format_decision_response(block_response)
            except Exception:
                checks.append("unsupported_block_semantics_explicit")
            else:
                failures.append("unsupported_block_semantics_not_explicit")

        if isinstance(adapter, InstallableControlAdapter):
            customer = {"customer_configuration": {"preserve": True}}
            try:
                plan = adapter.install_plan(customer)
                installed = adapter.install(plan, customer)
                if installed.configuration.get("customer_configuration") != customer["customer_configuration"]:
                    failures.append("installation_customer_configuration_modified")
                elif not adapter.validate_installation(installed.configuration):
                    failures.append("installation_validation_failed")
                elif adapter.uninstall(installed.configuration) != customer:
                    failures.append("uninstall_removed_customer_configuration")
                else:
                    checks.extend(("installation_transaction", "safe_uninstall"))
            except Exception as exc:
                failures.append(f"installation_lifecycle:{exc}")

        forbidden = [name for name in self._FORBIDDEN_EXECUTION_METHODS if hasattr(adapter, name)]
        if forbidden:
            failures.append(f"arbitrary_execution_channel:{forbidden[0]}")
        else:
            checks.append("no_arbitrary_execution_channel")
        if adapter.limitations():
            checks.append("structured_blind_spots")
        else:
            failures.append("structured_blind_spots_missing")
        return AdapterConformanceResult(
            adapter_id=adapter_id,
            passed=not failures,
            checks=tuple(checks),
            failures=tuple(failures),
            exemptions=(),
        )


def require_adapter_conformance(adapter: NativeControlAdapter) -> None:
    result = NativeControlAdapterConformanceSuite().run(adapter)
    if not result.passed:
        raise AdapterContractError("adapter_conformance_failed:" + ";".join(result.failures))
