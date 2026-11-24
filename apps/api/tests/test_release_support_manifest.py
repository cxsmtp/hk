from __future__ import annotations

from datetime import date
import importlib.util
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[3]
GENERATOR_PATH = ROOT / "infra" / "scripts" / "generate_release_support_manifest.py"


def _generator():
    spec = importlib.util.spec_from_file_location("release_support_manifest", GENERATOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture_repo(tmp_path: Path) -> Path:
    fixture_root = tmp_path / "repo"
    evidence = fixture_root / "docs" / "evidence"
    evidence.mkdir(parents=True)
    registry_names = (
        "claude-code-acceptance-registry.json",
        "codex-acceptance-registry.json",
        "gemini-cli-acceptance-registry.json",
        "cursor-acceptance-registry.json",
    )
    for registry_name in registry_names:
        source = ROOT / "docs" / "evidence" / registry_name
        payload = json.loads(source.read_text(encoding="utf-8"))
        shutil.copy2(source, evidence / registry_name)
        for row in payload.get("entries", []):
            artifact = row.get("evidence_artifact")
            if artifact:
                destination = fixture_root / artifact
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / artifact, destination)
    return fixture_root


def _registry_paths(repo_root: Path) -> dict[str, Path]:
    evidence = repo_root / "docs" / "evidence"
    return {
        "claude": evidence / "claude-code-acceptance-registry.json",
        "codex": evidence / "codex-acceptance-registry.json",
        "gemini": evidence / "gemini-cli-acceptance-registry.json",
        "cursor": evidence / "cursor-acceptance-registry.json",
    }


def test_current_authoritative_rows_and_capabilities_are_reported() -> None:
    generator = _generator()
    manifest = generator.build_manifest(ROOT, date(2026, 9, 24))

    rows = {
        (row["provider"], row["product"], row["provider_version"]): row
        for row in manifest["native_adapters"]
    }
    assert set(rows) == {
        ("anthropic", "claude_code", "2.1.183"),
        ("openai", "codex", "0.154.0"),
        ("google", "gemini_cli", "0.54.4"),
        ("google", "gemini_cli", "0.55.1"),
        ("cursor", "cursor", "2026.08.11-e8db854"),
    }
    assert rows[("anthropic", "claude_code", "2.1.183")]["provider_versions"] == ["2.1.183"]
    assert rows[("openai", "codex", "0.154.0")]["binary_sha256"] == (
        "4f85982624b3898c8991cb80c0981b2aa71070e3537046c9a95950318a95afcc"
    )
    assert rows[("openai", "codex", "0.154.0")]["capabilities"] == [
        "discovery",
        "identity",
        "prompt_control",
    ]
    assert "tool_control" in rows[("anthropic", "claude_code", "2.1.183")]["capabilities"]
    assert all(row["production_eligible"] is False for row in rows.values())
    assert all("expiry_missing" in row["statuses"] for row in rows.values())
    evidence = rows[("anthropic", "claude_code", "2.1.183")]["evidence"][0]
    assert len(evidence["source_registry"]["sha256"]) == 64
    assert evidence["evidence_artifact"]["declared_sha256"] == evidence["evidence_artifact"]["sha256"]


def test_invalid_raw_rows_remain_visible_and_artifact_failures_are_classified(tmp_path: Path) -> None:
    generator = _generator()
    fixture_root = _fixture_repo(tmp_path)
    paths = _registry_paths(fixture_root)
    registry_path = paths["claude"]
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["entries"].append({"provider": "anthropic", "product": "claude_code"})
    payload["entries"][0]["report_sha256"] = "0" * 64
    registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
    statuses = {item["status"] for item in manifest["diagnostics"] if item["registry"] == "claude"}
    assert "hash_mismatch" in statuses
    assert "registry_invalid" in statuses

    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["entries"][0]["report_sha256"] = "ec10ef" + "0" * 58
    artifact = fixture_root / payload["entries"][0]["evidence_artifact"]
    artifact.unlink()
    registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
    statuses = {item["status"] for item in manifest["diagnostics"] if item["registry"] == "claude"}
    assert "artifact_missing" in statuses


def test_stale_and_missing_expiry_are_explicit(tmp_path: Path) -> None:
    generator = _generator()
    fixture_root = _fixture_repo(tmp_path)
    paths = _registry_paths(fixture_root)
    registry_path = paths["claude"]
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["entries"][0]["expires_at"] = "2026-09-01T00:00:00Z"
    registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
    claude = next(row for row in manifest["native_adapters"] if row["provider"] == "anthropic")
    assert "stale" in claude["statuses"]
    assert claude["production_eligible"] is False

    payload["entries"][0].pop("expires_at")
    registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
    claude = next(row for row in manifest["native_adapters"] if row["provider"] == "anthropic")
    assert "expiry_missing" in claude["statuses"]


def test_duplicate_identity_is_rejected_instead_of_reusing_a_decoded_entry(tmp_path: Path) -> None:
    generator = _generator()
    fixture_root = _fixture_repo(tmp_path)
    paths = _registry_paths(fixture_root)
    registry_path = paths["claude"]
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    payload["entries"].append(dict(payload["entries"][0]))
    registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
    assert any(
        item["status"] == "registry_invalid"
        and item.get("reason") == "duplicate_or_ambiguous_identity"
        for item in manifest["diagnostics"]
    )
    assert not any(row["provider"] == "anthropic" for row in manifest["native_adapters"])


def test_production_permission_is_authoritative_and_capabilities_stay_per_version(tmp_path: Path) -> None:
    generator = _generator()
    fixture_root = _fixture_repo(tmp_path)
    paths = _registry_paths(fixture_root)
    claude_path = paths["claude"]
    claude_payload = json.loads(claude_path.read_text(encoding="utf-8"))
    claude_payload["entries"][0]["production_eligible"] = True
    claude_payload["entries"][0]["expires_at"] = "2099-01-01T00:00:00Z"
    claude_path.write_text(json.dumps(claude_payload, indent=2) + "\n", encoding="utf-8")

    gemini_path = paths["gemini"]
    gemini_payload = json.loads(gemini_path.read_text(encoding="utf-8"))
    gemini_payload["entries"][1]["accepted_capabilities"] = ["prompt_control"]
    gemini_path.write_text(json.dumps(gemini_payload, indent=2) + "\n", encoding="utf-8")

    manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
    claude = next(row for row in manifest["native_adapters"] if row["provider"] == "anthropic")
    assert claude["production_eligible"] is False
    assert claude["source_production_permitted"] is False
    versions = {
        row["provider_version"]: row
        for row in manifest["native_adapters"]
        if row["provider"] == "google"
    }
    assert versions["0.55.1"]["capabilities"] == ["prompt_control"]
    assert "tool_control" in versions["0.54.4"]["capabilities"]


def test_absolute_and_parent_artifact_paths_are_rejected_before_file_access(tmp_path: Path) -> None:
    generator = _generator()
    for artifact_name in ("/tmp/outside.json", "../outside.json"):
        fixture_root = _fixture_repo(tmp_path / artifact_name.replace("/", "_").replace("..", "parent"))
        paths = _registry_paths(fixture_root)
        registry_path = paths["claude"]
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        payload["entries"][0]["evidence_artifact"] = artifact_name
        registry_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        manifest = generator.build_manifest(fixture_root, date(2026, 9, 24), registry_paths=paths)
        assert any(
            item["status"] == "registry_invalid"
            and item.get("reason") == "artifact_path_must_be_relative"
            for item in manifest["diagnostics"]
        )


def test_flags_targets_and_deterministic_rendering_are_explicit(tmp_path: Path) -> None:
    generator = _generator()
    manifest = generator.build_manifest(ROOT, date(2026, 9, 24))
    flags = manifest["required_flags"]
    assert flags["native_control_framework"] is False
    assert flags["native_control_adapter_enforcement"] is False
    assert flags["native_control_anthropic"] is False
    assert flags["native_control_openai"] is False
    assert flags["native_control_google"] is False
    assert flags["native_control_cursor"] is False

    targets = {row["target"]: row for row in manifest["enterprise_targets"]}
    assert set(targets) == {
        "Entra ID",
        "Okta",
        "Splunk",
        "Rapid7",
        "Securonix",
        "Elastic",
        "Microsoft Sentinel",
    }
    assert all(row["status"] == "planned_unverified" for row in targets.values())
    assert all(row["implementation_evidenced"] is False for row in targets.values())
    assert all(row["tenant_acceptance_evidenced"] is False for row in targets.values())
    assert "serialization helper" in manifest["enterprise_targets_note"]

    rendered_one = generator.render_json(manifest)
    rendered_two = generator.render_json(generator.build_manifest(ROOT, date(2026, 9, 24)))
    assert rendered_one == rendered_two
    json_path = tmp_path / "manifest.json"
    markdown_path = tmp_path / "matrix.md"
    generator.write_outputs(manifest, json_path, markdown_path)
    assert generator.check_outputs(manifest, json_path, markdown_path) is True
    json_path.write_text(json_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert generator.check_outputs(manifest, json_path, markdown_path) is False
