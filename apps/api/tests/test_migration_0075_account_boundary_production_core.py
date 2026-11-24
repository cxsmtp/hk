from __future__ import annotations

from pathlib import Path


def test_0075_declares_additive_account_boundary_production_fields() -> None:
    api_root = Path(__file__).resolve().parents[1]
    source = (api_root / "app/db/migrations/versions/0075_account_boundary_production_core.py").read_text(encoding="utf-8")
    assert 'down_revision = "0074_ai_account_boundary"' in source
    for field in ("signed_envelope", "signing_algorithm", "max_uses", "consumed_state", "valid_until", "lifecycle_state", "route_health", "provider_version"):
        assert f'"{field}"' in source
