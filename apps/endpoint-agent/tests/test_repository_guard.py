from pathlib import Path
import subprocess

from hawk_endpoint_agent.native_control.repository_guard import (
    RepositoryOperation,
    classify_repository_command,
    classify_file_operation,
    resolve_repository_identity,
)


def test_repository_command_classification_is_fail_closed_and_operation_specific(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "origin", "https://github.com/Acme/Widget.git"],
        check=True,
    )

    assert classify_repository_command("git status", str(root)).operation is RepositoryOperation.READ
    assert classify_repository_command("git add README.md", str(root)).operation is RepositoryOperation.EDIT
    assert classify_repository_command("git commit -m change", str(root)).operation is RepositoryOperation.COMMIT
    assert classify_repository_command("git pull --ff-only origin main", str(root)).operation is RepositoryOperation.PULL
    assert classify_repository_command("git push origin main", str(root)).operation is RepositoryOperation.PUSH
    assert classify_repository_command("git status && git push", str(root)).blocked
    assert classify_repository_command("git -c alias.status=push status", str(root)).blocked
    assert classify_repository_command("git --git-dir=/tmp/other status", str(root)).blocked


def test_repository_resolution_ignores_inherited_git_environment(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "bound-repo"
    other = tmp_path / "other-repo"
    root.mkdir()
    other.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "alias.status")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "push")

    identity = resolve_repository_identity(root)

    assert identity.canonical_root == root.resolve()


def test_repository_identity_distinguishes_worktree_roots_with_shared_common_dir(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    worktree = tmp_path / "worktree"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        [
            "git", "-C", str(root), "-c", "user.name=fixture", "-c",
            "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "seed",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(root), "worktree", "add", "-q", str(worktree)], check=True)

    primary = resolve_repository_identity(root)
    linked = resolve_repository_identity(worktree)

    assert primary.canonical_root_hash != linked.canonical_root_hash
    assert primary.common_dir_hash == linked.common_dir_hash


def test_repository_command_rejects_expansions_mutating_metadata_and_unsafe_diff_options(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    marker = tmp_path / "expanded"
    commands = (
        f"git status $(touch {marker})",
        "git status *.py",
        "git status; git push origin main",
        "bash -c 'git push origin main'",
        "git status -p",
        "git config --global user.name fixture",
        "git diff --output=result.patch",
        "git diff --ext-diff",
        "git diff --textconv",
        "git diff --pager=cat",
    )

    for command in commands:
        assert classify_repository_command(command, str(root)).blocked, command
    for command in ("git branch feature/new", "git tag v1", "git config user.name fixture"):
        decision = classify_repository_command(command, str(root))
        assert decision.operation is RepositoryOperation.EDIT or decision.blocked, command
    assert not marker.exists()


def test_repository_push_and_pull_require_one_explicit_github_destination_and_ref(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "origin", "https://github.com/Acme/Widget.git"],
        check=True,
    )

    push = classify_repository_command("git push origin main", str(root))
    pull = classify_repository_command("git pull --ff-only origin main", str(root))
    assert push.operation is RepositoryOperation.PUSH
    assert pull.operation is RepositoryOperation.PULL
    assert push.destination_hash and len(push.destination_hash) == 64
    assert pull.destination_hash == push.destination_hash

    for command in (
        "git push",
        "git push origin",
        "git push origin main another",
        "git push https://github.com/Acme/Widget.git main",
        "git pull origin",
        "git pull origin main other",
        "git clone https://github.com/Acme/Widget.git",
    ):
        assert classify_repository_command(command, str(root)).blocked, command

    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "mirror", "https://github.com/Acme/Widget.git"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "remote", "set-url", "--add", "mirror", "https://github.com/Acme/Other.git"],
        check=True,
    )
    assert classify_repository_command("git push mirror main", str(root)).blocked
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "local", "file:///tmp/repo.git"],
        check=True,
    )
    assert classify_repository_command("git push local main", str(root)).blocked


def test_push_uses_effective_pushurl_instead_of_fetch_url(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "origin", "https://github.com/Acme/Widget.git"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "remote", "set-url", "--push", "origin", "https://github.com/Acme/Other.git"],
        check=True,
    )

    fetch = classify_repository_command("git pull origin main", str(root))
    push = classify_repository_command("git push origin main", str(root))

    assert fetch.destination_hash
    assert push.destination_hash
    assert fetch.destination_hash != push.destination_hash


def test_git_c_and_symlinked_root_resolve_to_the_same_canonical_folder(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)

    direct = classify_repository_command("git status", str(root))
    changed_directory = classify_repository_command(f"git -C {link} status", str(tmp_path))

    assert direct.identity is not None
    assert changed_directory.identity is not None
    assert direct.identity.canonical_root_hash == changed_directory.identity.canonical_root_hash


def test_file_operation_requires_one_explicit_target(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)

    assert classify_file_operation("", str(root), write=False).blocked
    assert classify_file_operation("", str(root), write=True).blocked


def test_repository_identity_exposes_only_hashes_and_resolves_symlinked_workspace(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)

    identity = resolve_repository_identity(link)
    assert identity.canonical_root_hash
    assert identity.common_dir_hash
    assert identity.target_hash
    assert str(root) not in identity.public_payload()
    assert "path" not in identity.public_payload()
