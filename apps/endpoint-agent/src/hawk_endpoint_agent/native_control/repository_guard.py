"""Fail-closed classification of local repository actions.

The classifier never runs a provider-supplied command. It uses fixed Git
queries to resolve local repository identity and emits only hashes and small
operation labels for the signed control callback.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
from urllib.parse import urlsplit


class RepositoryOperation(str, Enum):
    READ = "READ"
    EDIT = "EDIT"
    COMMIT = "COMMIT"
    PULL = "PULL"
    PUSH = "PUSH"


class RepositoryClassification(str, Enum):
    ALLOW = "ALLOW"
    BLOCKED = "BLOCKED"
    AMBIGUOUS = "AMBIGUOUS"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    """Canonical local roots with a hash-only public projection."""

    canonical_root: Path
    common_dir: Path
    target: Path
    canonical_root_hash: str
    common_dir_hash: str
    target_hash: str

    def public_payload(self) -> dict[str, str]:
        return {
            "canonical_root_sha256": self.canonical_root_hash,
            "common_dir_sha256": self.common_dir_hash,
            "target_sha256": self.target_hash,
        }


@dataclass(frozen=True, slots=True)
class RepositoryCommandDecision:
    classification: RepositoryClassification
    operation: RepositoryOperation | None = None
    reason: str = ""
    identity: RepositoryIdentity | None = None
    command_shape: str = "unknown"
    command_hash: str = "unknown"
    destination_hash: str | None = None

    @property
    def blocked(self) -> bool:
        return self.classification is not RepositoryClassification.ALLOW

    def signed_fields(self) -> dict[str, str]:
        resolution = {
            RepositoryClassification.ALLOW: "resolved",
            RepositoryClassification.BLOCKED: "blocked" if self.identity else "unavailable",
            RepositoryClassification.AMBIGUOUS: "ambiguous",
            RepositoryClassification.UNSUPPORTED: "unsupported",
        }[self.classification]
        fields = {
            "repository_control_resolution": resolution,
            "repository_operation": self.operation.value if self.operation else "UNKNOWN",
            "repository_command_shape": self.command_shape,
            "repository_command_hash": self.command_hash,
            "repository_destination_hash": self.destination_hash or "unknown",
            "repository_root_hash": "unknown",
            "repository_common_dir_hash": "unknown",
            "repository_target_hash": "unknown",
        }
        if self.identity:
            fields.update(
                repository_root_hash=self.identity.canonical_root_hash,
                repository_common_dir_hash=self.identity.common_dir_hash,
                repository_target_hash=self.identity.target_hash,
            )
        return fields


_SHELL_SYNTAX = re.compile(r"[;&|<>`\\\n\r$*?{}\[\]()!~%^]")
_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_CONFIG_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_REF_FORBIDDEN = ("..", "//", "@{", ".lock")


def _hash_text(value: Path | str) -> str:
    return hashlib.sha256(os.fsencode(str(value))).hexdigest()


def _git_environment() -> dict[str, str]:
    """Remove caller Git overrides before the fixed local metadata query."""

    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    return environment


def _local_path(value: str | os.PathLike[str], *, base: Path | None = None, require_exists: bool = False) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute() and base is not None:
        candidate = base / candidate
    if require_exists and not candidate.exists():
        raise ValueError("repository path does not exist")
    return Path(os.path.realpath(candidate))


def _within(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _identity(root: Path, common: Path, target: Path) -> RepositoryIdentity:
    return RepositoryIdentity(
        canonical_root=root,
        common_dir=common,
        target=target,
        canonical_root_hash=_hash_text(root),
        common_dir_hash=_hash_text(common),
        target_hash=_hash_text(target),
    )


def resolve_repository_identity(
    path: str | os.PathLike[str], target: str | os.PathLike[str] | None = None
) -> RepositoryIdentity:
    """Resolve exact folder and common Git roots without reading caller Git overrides."""

    workspace = _local_path(path, require_exists=True)
    if "\n" in str(workspace) or "\r" in str(workspace):
        raise ValueError("repository path is ambiguous")
    try:
        result = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "--show-toplevel", "--git-common-dir"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("repository workspace identity unavailable") from exc
    lines = result.stdout.splitlines()
    if len(lines) != 2:
        raise ValueError("repository workspace identity unavailable")
    root = _local_path(lines[0], base=workspace)
    common = _local_path(lines[1], base=workspace)
    target_path = _local_path(target or workspace, base=workspace)
    if not _within(root, target_path):
        raise ValueError("repository target is outside workspace")
    return _identity(root, common, target_path)


def _best_effort_identity(path: str | os.PathLike[str]) -> RepositoryIdentity | None:
    try:
        return resolve_repository_identity(path)
    except ValueError:
        return None


def _decision(
    classification: RepositoryClassification,
    reason: str,
    *,
    identity: RepositoryIdentity | None = None,
    operation: RepositoryOperation | None = None,
    command_shape: str = "unknown",
    command: str = "",
    destination_hash: str | None = None,
) -> RepositoryCommandDecision:
    return RepositoryCommandDecision(
        classification=classification,
        operation=operation,
        reason=reason,
        identity=identity,
        command_shape=command_shape,
        command_hash=_hash_text(command) if command else "unknown",
        destination_hash=destination_hash,
    )


def _valid_ref(value: str) -> bool:
    if not _REF.fullmatch(value) or value.startswith("-") or value.endswith(("/", ".")):
        return False
    return not any(part in value for part in _REF_FORBIDDEN)


def _canonical_github_locator(value: str) -> str:
    """Accept one HTTPS/SSH/scp GitHub repository locator and canonicalize it."""

    candidate = value.strip()
    scp = re.fullmatch(r"git@([A-Za-z0-9.-]+):([^:]+)", candidate)
    if scp:
        host = scp.group(1)
        path = scp.group(2)
    else:
        try:
            parsed = urlsplit(candidate)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("repository destination URL is unsupported") from exc
        if parsed.scheme not in {"https", "ssh"} or not parsed.hostname or port is not None:
            raise ValueError("repository destination URL is unsupported")
        if parsed.query or parsed.fragment or "%" in parsed.path or "\\" in parsed.path:
            raise ValueError("repository destination URL is unsupported")
        if parsed.scheme == "https" and (parsed.username or parsed.password):
            raise ValueError("repository destination credentials are unsupported")
        if parsed.scheme == "ssh" and (parsed.username != "git" or parsed.password):
            raise ValueError("repository destination credentials are unsupported")
        host = parsed.hostname
        path = parsed.path.lstrip("/")
    try:
        canonical_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("repository destination URL is unsupported") from exc
    if not canonical_host or not re.fullmatch(r"[a-z0-9.-]+", canonical_host):
        raise ValueError("repository destination URL is unsupported")
    parts = path.split("/")
    if len(parts) != 2:
        raise ValueError("repository destination URL is not one repository")
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not _REMOTE_NAME.fullmatch(owner) or not _REMOTE_NAME.fullmatch(repository):
        raise ValueError("repository destination URL is unsupported")
    return f"{canonical_host}/{owner.lower()}/{repository.lower()}"


def _destination_hash(remote: str, root: Path, *, push: bool) -> str:
    if "://" in remote or remote.startswith("git@"):
        # A literal URL can be rewritten by insteadOf/pushInsteadOf. Resolve
        # named remotes through Git so the hash reflects the effective target.
        raise ValueError("explicit repository URL rewrite cannot be resolved")
    else:
        if not _REMOTE_NAME.fullmatch(remote):
            raise ValueError("repository remote is ambiguous")
        arguments = ["git", "-C", str(root), "remote", "get-url"]
        if push:
            arguments.append("--push")
        arguments.extend(["--all", remote])
        try:
            result = subprocess.run(
                arguments,
                check=True,
                capture_output=True,
                text=True,
                timeout=3,
                env=_git_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("repository remote resolution unavailable") from exc
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(urls) != 1:
            raise ValueError("repository remote is ambiguous")
        locator = urls[0]
    return _hash_text(_canonical_github_locator(locator))


def _read_command(subcommand: str, arguments: list[str]) -> tuple[RepositoryOperation | None, str | None]:
    if subcommand == "status":
        allowed = {"--short", "-s", "--branch", "-b", "--porcelain"}
        return (RepositoryOperation.READ, "git_status") if all(arg in allowed for arg in arguments) else (None, None)
    if subcommand == "diff":
        denied = {"--output", "--ext-diff", "--textconv", "--pager", "--no-ext-diff", "--no-textconv"}
        safe = {"--cached", "--staged", "--stat", "--name-only", "--name-status", "--check"}
        if any(arg.split("=", 1)[0] in denied for arg in arguments):
            return None, None
        if all(arg in safe for arg in arguments):
            return RepositoryOperation.READ, "git_diff"
        return None, None
    if subcommand in {"log", "show", "ls-files", "ls-tree"}:
        return (RepositoryOperation.READ, f"git_{subcommand}") if not arguments else (None, None)
    if subcommand in {"branch", "tag"}:
        if not arguments or arguments == ["--list"] or arguments == ["-l"]:
            return RepositoryOperation.READ, f"git_{subcommand}_list"
        return None, None
    if subcommand == "config":
        if arguments == ["--list"] or arguments == ["-l"]:
            return RepositoryOperation.READ, "git_config_list"
        if len(arguments) == 2 and arguments[0] in {"--get", "--get-all"} and _CONFIG_KEY.fullmatch(arguments[1]):
            return RepositoryOperation.READ, "git_config_get"
        return None, None
    if subcommand == "rev-parse" and arguments == ["--show-toplevel"]:
        return RepositoryOperation.READ, "git_rev_parse"
    return None, None


def _mutation_command(subcommand: str, arguments: list[str]) -> tuple[RepositoryOperation | None, str | None]:
    if subcommand == "add" and len(arguments) == 1 and _valid_ref(arguments[0]):
        return RepositoryOperation.EDIT, "git_add"
    if subcommand == "commit" and len(arguments) == 2 and arguments[0] in {"-m", "--message"} and arguments[1].strip():
        return RepositoryOperation.COMMIT, "git_commit"
    if subcommand == "branch" and len(arguments) == 1 and _valid_ref(arguments[0]):
        return RepositoryOperation.EDIT, "git_branch_write"
    if subcommand == "tag" and len(arguments) == 1 and _valid_ref(arguments[0]):
        return RepositoryOperation.EDIT, "git_tag_write"
    if subcommand == "config" and len(arguments) in {2, 3} and _CONFIG_KEY.fullmatch(arguments[0]):
        return RepositoryOperation.EDIT, "git_config_write"
    if subcommand == "config" and len(arguments) == 2 and arguments[0] in {"--unset", "--unset-all"} and _CONFIG_KEY.fullmatch(arguments[1]):
        return RepositoryOperation.EDIT, "git_config_write"
    return None, None


def classify_repository_command(command: str, cwd: str | os.PathLike[str]) -> RepositoryCommandDecision:
    """Classify a narrow set of explicit local Git operations; ambiguity blocks."""

    identity_hint = _best_effort_identity(cwd)
    if not isinstance(command, str) or not command.strip():
        return _decision(RepositoryClassification.AMBIGUOUS, "empty_command", identity=identity_hint, command=command if isinstance(command, str) else "")
    if _SHELL_SYNTAX.search(command):
        return _decision(RepositoryClassification.AMBIGUOUS, "compound_or_shell_syntax", identity=identity_hint, command_shape="ambiguous_command", command=command)
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return _decision(RepositoryClassification.AMBIGUOUS, "invalid_shell_syntax", identity=identity_hint, command_shape="ambiguous_command", command=command)
    if not tokens or tokens[0] != "git":
        return _decision(RepositoryClassification.UNSUPPORTED, "unsupported_command", identity=identity_hint, command_shape="unsupported_command", command=command)

    try:
        command_cwd = _local_path(cwd, require_exists=True)
    except ValueError:
        return _decision(RepositoryClassification.BLOCKED, "repository_workspace_unavailable", command_shape="git_unknown", command=command)
    index = 1
    seen_c = False
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        if option != "-C" or seen_c or index + 1 >= len(tokens):
            return _decision(RepositoryClassification.AMBIGUOUS, "unsupported_git_option", identity=identity_hint, command_shape="git_global_option", command=command)
        try:
            command_cwd = _local_path(tokens[index + 1], base=command_cwd, require_exists=True)
        except ValueError:
            return _decision(RepositoryClassification.BLOCKED, "git_directory_unavailable", identity=identity_hint, command_shape="git_c", command=command)
        seen_c = True
        index += 2
    if index >= len(tokens) or tokens[index].startswith("-"):
        return _decision(RepositoryClassification.AMBIGUOUS, "missing_git_subcommand", identity=identity_hint, command_shape="git_unknown", command=command)
    subcommand = tokens[index].lower()
    arguments = tokens[index + 1 :]
    try:
        identity = resolve_repository_identity(command_cwd)
    except ValueError:
        return _decision(RepositoryClassification.BLOCKED, "repository_workspace_unavailable", identity=identity_hint, command_shape=f"git_{subcommand}", command=command)

    if subcommand in {"push", "pull", "fetch"}:
        operation = RepositoryOperation.PUSH if subcommand == "push" else RepositoryOperation.PULL
        remote_args = arguments
        if subcommand == "pull" and remote_args[:1] == ["--ff-only"]:
            remote_args = remote_args[1:]
        if len(remote_args) != 2 or not _valid_ref(remote_args[1]):
            return _decision(RepositoryClassification.AMBIGUOUS, "repository_remote_or_ref_ambiguous", identity=identity, command_shape=f"git_{subcommand}", command=command)
        try:
            destination_hash = _destination_hash(
                remote_args[0], identity.canonical_root, push=subcommand == "push"
            )
        except ValueError:
            return _decision(RepositoryClassification.AMBIGUOUS, "repository_destination_unavailable", identity=identity, command_shape=f"git_{subcommand}", command=command)
        if subcommand == "fetch":
            return _decision(RepositoryClassification.UNSUPPORTED, "fetch_shape_unsupported", identity=identity, command_shape="git_fetch", command=command, destination_hash=destination_hash)
        return _decision(RepositoryClassification.ALLOW, "classified_git_operation", identity=identity, operation=operation, command_shape=f"git_{subcommand}", command=command, destination_hash=destination_hash)
    if subcommand == "clone":
        return _decision(RepositoryClassification.UNSUPPORTED, "clone_unsupported", identity=identity, command_shape="git_clone", command=command)

    operation, shape = _read_command(subcommand, arguments)
    if operation:
        return _decision(RepositoryClassification.ALLOW, "classified_git_operation", identity=identity, operation=operation, command_shape=shape or "git_read", command=command)
    operation, shape = _mutation_command(subcommand, arguments)
    if operation:
        return _decision(RepositoryClassification.ALLOW, "classified_git_operation", identity=identity, operation=operation, command_shape=shape or "git_edit", command=command)
    return _decision(RepositoryClassification.UNSUPPORTED, "git_command_shape_unsupported", identity=identity, command_shape=f"git_{subcommand}", command=command)


def classify_file_operation(
    path: str | os.PathLike[str], cwd: str | os.PathLike[str], *, write: bool
) -> RepositoryCommandDecision:
    """Classify one local target within the exact canonical Git folder."""

    shape = "file_write" if write else "file_read"
    try:
        target_value = os.fspath(path)
    except TypeError:
        target_value = ""
    if not target_value.strip():
        return _decision(
            RepositoryClassification.AMBIGUOUS,
            "repository_target_unavailable",
            identity=_best_effort_identity(cwd),
            command_shape=shape,
        )
    try:
        base = _local_path(cwd, require_exists=True)
        root_identity = resolve_repository_identity(base)
        target = _local_path(target_value, base=base)
        identity = _identity(root_identity.canonical_root, root_identity.common_dir, target)
    except ValueError:
        return _decision(RepositoryClassification.BLOCKED, "repository_workspace_unavailable", command_shape=shape)
    if not _within(identity.canonical_root, target):
        return _decision(RepositoryClassification.BLOCKED, "repository_target_outside_workspace", identity=identity, command_shape=shape)
    return _decision(
        RepositoryClassification.ALLOW,
        "classified_file_operation",
        identity=identity,
        operation=RepositoryOperation.EDIT if write else RepositoryOperation.READ,
        command_shape=shape,
        command=target_value,
    )


__all__ = [
    "RepositoryClassification",
    "RepositoryCommandDecision",
    "RepositoryIdentity",
    "RepositoryOperation",
    "classify_file_operation",
    "classify_repository_command",
    "resolve_repository_identity",
]
