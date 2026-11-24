from app.services.simulation_service import _simulation_request_id


def test_simulation_request_identity_fits_postgresql_and_preserves_recursion_guard():
    identity = {"run_id": "12345678-1234-1234-1234-123456789012", "step_id": "long-step-" * 20, "base_request_id": "caller-request-" * 30, "iteration": None}
    value = _simulation_request_id(**identity)
    assert value.startswith("sim-")
    assert len(value) == 36
    assert _simulation_request_id(**identity) == value
    variants = [
        {**identity, "run_id": "another-run"},
        {**identity, "step_id": "another-step"},
        {**identity, "base_request_id": "another-request"},
        {**identity, "iteration": 1},
        {**identity, "iteration": 2},
    ]
    values = [value, *(_simulation_request_id(**item) for item in variants)]
    assert len(set(values)) == len(values)
    assert all(len(item) == 36 and item.startswith("sim-") for item in values)
