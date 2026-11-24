from app.services.native_control.acceptance_versions import (
    REAL_BINARY_ACCEPTANCE_VERSION,
    acceptance_version_is_current,
)


def test_real_binary_acceptance_rejects_legacy_v1() -> None:
    assert acceptance_version_is_current(
        acceptance_state="REAL_BINARY_ACCEPTED",
        validation_version=REAL_BINARY_ACCEPTANCE_VERSION,
    )
    assert not acceptance_version_is_current(
        acceptance_state="REAL_BINARY_ACCEPTED",
        validation_version="native-control-real-binary-acceptance/1.0",
    )


def test_non_binary_acceptance_version_is_owned_by_its_separate_contract() -> None:
    assert acceptance_version_is_current(
        acceptance_state="REAL_ENTERPRISE_TENANT_ACCEPTED",
        validation_version="native-control-validation/2.0",
    )
