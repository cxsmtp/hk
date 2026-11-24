from __future__ import annotations

import json

import pytest

from app.services.hmair.exposure.category_catalog import (
    SUPPORTED_EXPOSURE_CAPABILITY_SELECTORS,
    load_category_catalog,
)


EXPECTED_CATEGORY_IDS = {
    "coding_exposure",
    "research_exposure",
    "customer_data_exposure",
    "financial_exposure",
    "cloud_exposure",
    "identity_exposure",
    "database_exposure",
    "secrets_exposure",
    "mcp_exposure",
    "model_exposure",
    "runtime_exposure",
    "external_ai_exposure",
    "shadow_ai_exposure",
    "developer_exposure",
    "workflow_exposure",
    "persistent_side_effect_exposure",
    "unknown_exposure",
}


def test_catalog_is_complete_versioned_immutable_and_digestible() -> None:
    catalog = load_category_catalog()
    assert catalog.version == "1.1.0"
    assert {item.category_id for item in catalog.categories} == EXPECTED_CATEGORY_IDS
    assert tuple(sorted(catalog.categories, key=lambda item: item.category_id)) == catalog.categories
    assert len(catalog.digest) == 64
    assert catalog.digest == load_category_catalog().digest


def test_catalog_rejects_duplicate_category_ids(tmp_path) -> None:
    source = load_category_catalog()
    payload = source.model_dump(mode="json", exclude={"digest"})
    payload["categories"].append(payload["categories"][0])
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate category IDs"):
        load_category_catalog(path)


def test_catalog_rejects_unknown_dimensions_and_capabilities(tmp_path) -> None:
    source = load_category_catalog()
    payload = source.model_dump(mode="json", exclude={"digest"})
    payload["categories"][0]["required_dimensions"] = ["marketing_score"]
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid exposure category catalog"):
        load_category_catalog(path)


def test_only_unknown_category_may_have_no_qualifying_capability(tmp_path) -> None:
    source = load_category_catalog()
    payload = source.model_dump(mode="json", exclude={"digest"})
    target = next(item for item in payload["categories"] if item["category_id"] == "coding_exposure")
    target["qualifying_capabilities"] = []
    path = tmp_path / "empty-selector.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="qualifying capability"):
        load_category_catalog(path)


def test_catalog_requires_semantic_version(tmp_path) -> None:
    source = load_category_catalog()
    payload = source.model_dump(mode="json", exclude={"digest"})
    payload["version"] = "latest"
    path = tmp_path / "unversioned.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid exposure category catalog"):
        load_category_catalog(path)


def test_every_catalog_selector_is_producible_by_a_reviewed_source_authority() -> None:
    catalog = load_category_catalog()
    selectors = {
        selector
        for category in catalog.categories
        for selector in category.qualifying_capabilities
    }

    assert selectors <= SUPPORTED_EXPOSURE_CAPABILITY_SELECTORS
    assert "mcp_client" in selectors
    assert "MCP_client" not in selectors
