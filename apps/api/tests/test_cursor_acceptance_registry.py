from __future__ import annotations

import json
from pathlib import Path

from app.services.native_control.cursor_acceptance_registry import (
    load_cursor_acceptance_registry,
)


def test_cursor_registry_accepts_only_hash_bound_reviewed_exact_release_evidence() -> None:
    registry = load_cursor_acceptance_registry()

    assert registry.accepted_versions(adapter_version="0.2.0") == (
        "2026.08.11-e8db854",
    )
    entry = registry.entry("2026.08.11-e8db854", adapter_version="0.2.0")
    assert entry is not None
    assert entry.desktop_version == "3.15.6"
    assert entry.desktop_commit == "a1f686545fd0ce8917bbd2449f733551a9bce420"
    assert entry.production_eligible is False
    assert "command_control" in entry.accepted_capabilities
    assert "delegation_control" not in entry.accepted_capabilities
    assert registry.assurance(
        "2026.08.11-e8db854",
        adapter_version="0.2.0",
    ) == "exact_verified"
    assert registry.assurance("9.9.9", adapter_version="0.2.0") == "unsupported"


def test_cursor_registry_rejects_tampered_acceptance_artifact(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[3]
    source_registry = repository / "docs/evidence/cursor-acceptance-registry.json"
    source_artifact = (
        repository
        / "docs/evidence/cursor-2026.08.11-e8db854-acceptance-result.json"
    )
    evidence = tmp_path / "docs/evidence"
    evidence.mkdir(parents=True)
    registry_path = evidence / "cursor-acceptance-registry.json"
    artifact_path = evidence / "cursor-2026.08.11-e8db854-acceptance-result.json"
    registry_path.write_bytes(source_registry.read_bytes())
    artifact_path.write_bytes(source_artifact.read_bytes())

    assert load_cursor_acceptance_registry(registry_path).entries

    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    payload["passed"] = False
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    assert load_cursor_acceptance_registry(registry_path).entries == ()
