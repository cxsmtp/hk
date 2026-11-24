from app.services.native_control.validation_runner import run_safe_synthetic_validation


def test_endpoint_runtime_validation_proves_allow_and_block_without_external_callback() -> None:
    calls: list[str] = []

    checks = run_safe_synthetic_validation(
        tenant_id="tenant-1",
        integration_id="integration-1",
        integration_method="endpoint_runtime",
        profile_verified=True,
        pre_execution_capable=True,
        route_binding_configured=True,
        live_route_observed=True,
        endpoint_probe=lambda decision: calls.append(decision) or {
            "decision": decision,
            "control_mode": "inline_allowed" if decision == "allow" else "inline_prevented",
            "protected_callback_executed": decision == "allow",
            "route_verified": True,
        },
    )

    assert calls == ["allow", "block"]
    assert checks["server_probe_supported"] is True
    assert checks["allow_behavior"] is True
    assert checks["block_behavior"] is True
    assert checks["protected_callback_not_executed"] is True


def test_endpoint_runtime_validation_fails_closed_without_live_verified_route() -> None:
    checks = run_safe_synthetic_validation(
        tenant_id="tenant-1",
        integration_id="integration-1",
        integration_method="endpoint_runtime",
        profile_verified=True,
        pre_execution_capable=True,
        route_binding_configured=True,
        live_route_observed=False,
    )

    assert checks["server_probe_supported"] is False
    assert checks["allow_behavior"] is False
    assert checks["block_behavior"] is False
    assert checks["protected_callback_not_executed"] is False

