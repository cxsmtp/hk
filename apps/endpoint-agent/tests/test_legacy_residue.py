from __future__ import annotations

from pathlib import Path

from hawk_endpoint_agent.legacy_residue import cleanup_legacy_bootstrap_files


def test_cleanup_removes_only_exact_regular_legacy_files(tmp_path: Path) -> None:
    root = tmp_path / "bootstrap"
    root.mkdir()
    (root / "agent-token").write_text("old-agent-secret", encoding="utf-8")
    (root / "operator-token").write_text("old-operator-secret", encoding="utf-8")
    (root / "tenant-id").write_text("old-tenant", encoding="utf-8")
    (root / "keep.json").write_text("keep", encoding="utf-8")

    result = cleanup_legacy_bootstrap_files(root)

    assert not (root / "agent-token").exists()
    assert not (root / "operator-token").exists()
    assert not (root / "tenant-id").exists()
    assert (root / "keep.json").read_text(encoding="utf-8") == "keep"
    assert result.removed == ("agent-token", "operator-token", "tenant-id")
    assert "old-agent-secret" not in repr(result)
    assert result.residue_present is False


def test_cleanup_refuses_symlink_and_reports_residue(tmp_path: Path) -> None:
    root = tmp_path / "bootstrap"
    root.mkdir()
    target = tmp_path / "outside-secret"
    target.write_text("must-survive", encoding="utf-8")
    (root / "agent-token").symlink_to(target)

    result = cleanup_legacy_bootstrap_files(root)

    assert (root / "agent-token").is_symlink()
    assert target.read_text(encoding="utf-8") == "must-survive"
    assert result.removed == ()
    assert result.residue_present is True
