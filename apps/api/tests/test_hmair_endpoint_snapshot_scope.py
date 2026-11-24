from app.services.endpoint_identity_service import DEFAULT_ENDPOINT_SCOPES


def test_new_endpoint_enrollment_includes_dedicated_hmair_snapshot_scope() -> None:
    assert "endpoint:discovery:write" in DEFAULT_ENDPOINT_SCOPES
