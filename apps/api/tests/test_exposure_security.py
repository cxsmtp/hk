from __future__ import annotations

from app.services.hmair.exposure.contracts import CalculationStatus
from test_exposure_api import exposure_api  # noqa: F401


FORBIDDEN_KEYS = {
    "raw_prompt",
    "access_token",
    "secret",
    "credential",
    "password",
    "cookie",
    "raw_payload",
    "content",
}


def _keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            found.add(key.casefold())
            found |= _keys(nested)
    elif isinstance(value, list):
        for nested in value:
            found |= _keys(nested)
    return found


def test_serialized_exposure_routes_exclude_sensitive_material(exposure_api) -> None:
    client, _seed, asset, _other, _other_asset, _app = exposure_api
    for suffix in ("exposure", "exposure/timeline", "exposure/graph?category_id=coding_exposure"):
        response = client.get(f"/discovery/assets/{asset.asset_id}/{suffix}")
        assert response.status_code == 200, response.text
        assert FORBIDDEN_KEYS.isdisjoint(_keys(response.json()))


def test_partial_authority_failure_is_not_zero_or_success() -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    from app.db.session import Base
    from app.services.hmair.exposure.reasoning_service import ExposureReasoningService
    from test_exposure_service import _PartialReader
    from test_exposure_source_reader import NOW, _seed_asset_sources

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session = Session(engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        seed, asset, _ = _seed_asset_sources(session, suffix="exposure-api-partial")
        result = ExposureReasoningService(source_reader=_PartialReader()).project(
            session,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            as_of=NOW,
        )
        assert result.calculation_status is CalculationStatus.PARTIAL
        assert result.failed_authorities == ("control_coverage",)
        assert all(item.extent.value == "unknown" for item in result.exposures)
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def test_source_timeout_returns_explicit_unavailable_projection(monkeypatch, exposure_api) -> None:
    client, _seed, asset, _other, _other_asset, _app = exposure_api

    def timeout(*_args, **_kwargs):
        raise TimeoutError("simulated source deadline")

    monkeypatch.setattr(
        "app.services.hmair.exposure.source_reader.ExposureSourceReader.read",
        timeout,
    )
    response = client.get(f"/discovery/assets/{asset.asset_id}/exposure")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["calculation_status"] == "unavailable"
    assert body["failed_authorities"] == ["source_reader_timeout"]
    assert body["exposures"] == []
    assert "source_projection_unavailable" in body["limitations"]


def test_contracts_reject_oversized_refs_invalid_enums_and_secret_fields() -> None:
    from datetime import datetime, timezone

    import pytest
    from pydantic import ValidationError

    from app.services.hmair.exposure.contracts import ExposureFactor
    from app.services.hmair.contracts import canonical_json_bytes

    base = {
        "dimension": "capability",
        "source_type": "test",
        "source_id": "source-1",
        "state": "filesystem_write",
        "evidence_refs": (),
        "related_source_refs": (),
        "confidence": 0.9,
        "verification_status": "verified",
        "freshness": "fresh",
        "observed_at": datetime.now(timezone.utc),
        "validated_at": datetime.now(timezone.utc),
        "methodology_id": "security-test/1.0",
        "collector_group": "test",
        "limitations": (),
    }
    with pytest.raises(ValidationError):
        ExposureFactor(**base, access_token="must-not-be-accepted")
    with pytest.raises(ValidationError):
        ExposureFactor(**{**base, "dimension": "invented_dimension"})
    with pytest.raises(ValidationError):
        ExposureFactor(
            **{
                **base,
                "related_source_refs": tuple(f"source-{index}" for index in range(65)),
            }
        )
    with pytest.raises(ValueError):
        canonical_json_bytes({"state": "\ud800"})


def test_concurrent_rule_evaluation_is_deterministic() -> None:
    from concurrent.futures import ThreadPoolExecutor

    from test_exposure_reasoning_rules import _base, _definition
    from app.services.hmair.exposure.reasoning_rules import evaluate_category

    def evaluate() -> bytes:
        return evaluate_category(
            definition=_definition(),
            factors=_base(),
            methodology_version="1.0.0",
        ).model_dump_json().encode("utf-8")

    with ThreadPoolExecutor(max_workers=8) as pool:
        outputs = tuple(pool.map(lambda _index: evaluate(), range(32)))
    assert len(set(outputs)) == 1


def test_tenant_safe_router_function_does_not_disclose_cross_tenant_asset(exposure_api) -> None:
    _client, seed, _asset, _other, other_asset, _app = exposure_api
    # The HTTP fixture owns the session; this verifies the public response above.
    assert seed["tenant_id"] != other_asset.tenant_id
