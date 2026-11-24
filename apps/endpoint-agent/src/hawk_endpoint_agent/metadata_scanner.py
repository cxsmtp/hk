"""Bounded, one-shot, privacy-preserving endpoint product metadata discovery.

The scanner deliberately uses only fixed product/configuration locations and
allowlisted metadata fields. It does not inspect arbitrary user files, execute
discovered binaries, contact the network, upload results, or persist state.
"""

from __future__ import annotations

import json
import errno
import os
import plistlib
import re
import stat
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit


SCHEMA_VERSION = "hawk.endpoint_metadata.v1"
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_SCANDIR_SUPPORTS_FD = os.scandir in os.supports_fd


@dataclass(frozen=True)
class ScanLimits:
    """Hard ceilings for a single scanner invocation."""

    max_roots: int = 16
    max_files: int = 64
    max_file_bytes: int = 64 * 1024
    max_items: int = 128
    max_directory_entries: int = 256
    max_seconds: float = 2.0

    def __post_init__(self) -> None:
        if min(
            self.max_roots,
            self.max_files,
            self.max_file_bytes,
            self.max_items,
            self.max_directory_entries,
        ) < 1:
            raise ValueError("scan limits must be positive")
        if self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive")


@dataclass(frozen=True)
class ScanRoots:
    """Injectable roots; each probe below them is still a fixed relative path."""

    home: Path
    application_roots: tuple[Path, ...]
    executable_roots: tuple[Path, ...]

    @classmethod
    def defaults(
        cls,
        *,
        environ: Mapping[str, str] | None = None,
        platform: str | None = None,
    ) -> "ScanRoots":
        environment = os.environ if environ is None else environ
        home = Path(environment.get("HOME") or Path.home())
        platform_name = (platform or sys.platform).lower()

        if platform_name == "darwin":
            application_roots = (Path("/Applications"), home / "Applications")
        elif platform_name.startswith("win"):
            local_apps = environment.get("LOCALAPPDATA")
            application_roots = (
                (Path(local_apps) / "Programs",) if local_apps else ()
            )
        else:
            application_roots = (Path("/opt"), home / ".local/share/applications")

        executable_roots: list[Path] = []
        for raw_root in environment.get("PATH", "").split(os.pathsep):
            if not raw_root:
                continue
            root = Path(raw_root)
            if root not in executable_roots:
                executable_roots.append(root)

        return cls(
            home=home,
            application_roots=tuple(application_roots),
            executable_roots=tuple(executable_roots),
        )


@dataclass(frozen=True)
class ProbeEntry:
    name: str
    is_dir: bool
    is_file: bool
    is_symlink: bool


class ProbeFailure(Exception):
    """An internal error represented externally by a stable privacy-safe code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class FilesystemProbe(Protocol):
    def stat_relative(
        self,
        root: Path,
        relative: str | Path,
    ) -> os.stat_result: ...

    def list_directory(
        self,
        root: Path,
        relative: str | Path,
        max_entries: int,
    ) -> tuple[ProbeEntry, ...]: ...

    def read_limited(
        self,
        root: Path,
        relative: str | Path,
        max_bytes: int,
    ) -> bytes: ...


class LocalFilesystemProbe:
    """Descriptor-relative local probes that never follow symlink components."""

    @staticmethod
    def _validate_relative(relative: str | Path) -> tuple[str, ...]:
        relative_path = Path(relative)
        parts = relative_path.parts
        if (
            relative_path.is_absolute()
            or not parts
            or any(part in ("", ".", "..") for part in parts)
        ):
            raise ProbeFailure("invalid_probe_path")
        return parts

    @staticmethod
    def _error_code(exc: OSError) -> str:
        if exc.errno == errno.ENOENT:
            return "missing"
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return "symlink_skipped"
        if exc.errno in (errno.EACCES, errno.EPERM):
            return "metadata_unreadable"
        return "metadata_unreadable"

    @staticmethod
    def _flags(*, directory: bool) -> int:
        required = ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")
        if any(not hasattr(os, name) for name in required):
            raise ProbeFailure("unsupported_platform")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        if directory:
            flags |= os.O_DIRECTORY
        return flags

    @staticmethod
    def _absolute_root_components(root: Path) -> tuple[str, ...]:
        if os.name != "posix":
            raise ProbeFailure("unsupported_platform")
        root_text = os.fspath(root)
        if (
            not isinstance(root_text, str)
            or "\x00" in root_text
            or not root_text.startswith("/")
            or root_text.startswith("//")
        ):
            raise ProbeFailure("invalid_root")
        if root_text == "/":
            return ()
        components = tuple(root_text.split("/")[1:])
        if any(component in ("", ".", "..") for component in components):
            raise ProbeFailure("invalid_root")
        return components

    def _open_root(self, root: Path, directory_flags: int) -> int:
        components = self._absolute_root_components(root)
        current_fd = -1
        try:
            current_fd = os.open("/", directory_flags)
            for component in components:
                next_fd = os.open(
                    component,
                    directory_flags,
                    dir_fd=current_fd,
                )
                os.close(current_fd)
                current_fd = next_fd
            root_fd = current_fd
            current_fd = -1
            return root_fd
        except ProbeFailure:
            raise
        except OSError as exc:
            raise ProbeFailure(self._error_code(exc)) from exc
        finally:
            if current_fd >= 0:
                os.close(current_fd)

    def _open_relative(
        self,
        root: Path,
        relative: str | Path,
        *,
        final_directory: bool,
    ) -> int:
        if not _OPEN_SUPPORTS_DIR_FD:
            raise ProbeFailure("unsupported_platform")
        parts = self._validate_relative(relative)
        directory_flags = self._flags(directory=True)
        final_flags = self._flags(directory=final_directory)
        current_fd = -1
        try:
            current_fd = self._open_root(root, directory_flags)
            for component in parts[:-1]:
                next_fd = os.open(
                    component,
                    directory_flags,
                    dir_fd=current_fd,
                )
                os.close(current_fd)
                current_fd = next_fd
            final_fd = os.open(
                parts[-1],
                final_flags,
                dir_fd=current_fd,
            )
            return final_fd
        except ProbeFailure:
            raise
        except OSError as exc:
            raise ProbeFailure(self._error_code(exc)) from exc
        finally:
            if current_fd >= 0:
                os.close(current_fd)

    def stat_relative(
        self,
        root: Path,
        relative: str | Path,
    ) -> os.stat_result:
        descriptor = self._open_relative(
            root,
            relative,
            final_directory=False,
        )
        try:
            return os.fstat(descriptor)
        finally:
            os.close(descriptor)

    def list_directory(
        self,
        root: Path,
        relative: str | Path,
        max_entries: int,
    ) -> tuple[ProbeEntry, ...]:
        if not _SCANDIR_SUPPORTS_FD:
            raise ProbeFailure("unsupported_platform")
        descriptor = self._open_relative(
            root,
            relative,
            final_directory=True,
        )
        try:
            with os.scandir(descriptor) as entries:
                result: list[ProbeEntry] = []
                for entry in entries:
                    result.append(
                        ProbeEntry(
                            name=entry.name,
                            is_dir=entry.is_dir(follow_symlinks=False),
                            is_file=entry.is_file(follow_symlinks=False),
                            is_symlink=entry.is_symlink(),
                        )
                    )
                    if len(result) > max_entries:
                        break
        except OSError as exc:
            raise ProbeFailure(self._error_code(exc)) from exc
        finally:
            os.close(descriptor)
        return tuple(sorted(result, key=lambda entry: entry.name))

    def read_limited(
        self,
        root: Path,
        relative: str | Path,
        max_bytes: int,
    ) -> bytes:
        descriptor = self._open_relative(
            root,
            relative,
            final_directory=False,
        )
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ProbeFailure("unsupported_file_type")
            if file_stat.st_size > max_bytes:
                raise ProbeFailure("oversized_metadata")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > max_bytes:
                raise ProbeFailure("oversized_metadata")
            return data
        except OSError as exc:
            raise ProbeFailure(self._error_code(exc)) from exc
        finally:
            os.close(descriptor)


@dataclass(frozen=True)
class _ProductSpec:
    id: str
    name: str
    provider: str
    category: str
    executable_names: tuple[str, ...] = ()
    application_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ConfigSpec:
    product_id: str
    source: str
    relative_path: str
    format: str


_PRODUCTS = (
    _ProductSpec("chatgpt_desktop", "ChatGPT Desktop", "openai", "desktop", application_names=("ChatGPT.app", "ChatGPT")),
    _ProductSpec("claude_desktop", "Claude Desktop", "anthropic", "desktop", application_names=("Claude.app", "Claude")),
    _ProductSpec("ollama", "Ollama", "ollama", "local_model_runner", executable_names=("ollama", "ollama.exe"), application_names=("Ollama.app", "Ollama")),
    _ProductSpec("lm_studio", "LM Studio", "lmstudio", "local_model_runner", application_names=("LM Studio.app", "LM Studio")),
    _ProductSpec(
        "claude_code",
        "Claude Code",
        "anthropic",
        "cli",
        executable_names=("claude", "claude.exe"),
    ),
    _ProductSpec(
        "codex_cli",
        "Codex CLI",
        "openai",
        "cli",
        executable_names=("codex", "codex.exe"),
    ),
    _ProductSpec(
        "cursor",
        "Cursor",
        "cursor",
        "ide",
        executable_names=("cursor", "cursor.exe"),
        application_names=("Cursor.app", "Cursor"),
    ),
    _ProductSpec(
        "windsurf",
        "Windsurf",
        "codeium",
        "ide",
        executable_names=("windsurf", "windsurf.exe"),
        application_names=("Windsurf.app", "Windsurf"),
    ),
    _ProductSpec("copilot", "GitHub Copilot", "github", "ide_extension"),
)

_CONFIGS = (
    _ConfigSpec("claude_code", "claude_settings", ".claude/settings.json", "json"),
    _ConfigSpec("claude_code", "claude_user_config", ".claude.json", "json"),
    _ConfigSpec("codex_cli", "codex_config", ".codex/config.toml", "toml"),
    _ConfigSpec("cursor", "cursor_mcp_config", ".cursor/mcp.json", "json"),
    _ConfigSpec(
        "windsurf",
        "windsurf_mcp_config",
        ".codeium/windsurf/mcp_config.json",
        "json",
    ),
    _ConfigSpec("windsurf", "windsurf_user_mcp_config", ".windsurf/mcp.json", "json"),
    _ConfigSpec("mcp_agent_config", "generic_mcp_config", ".config/mcp/config.json", "json"),
    _ConfigSpec("mcp_agent_config", "home_mcp_config", ".mcp.json", "json"),
)

_IDE_EXTENSION_ROOTS = (
    ("vscode", ".vscode/extensions"),
    ("cursor", ".cursor/extensions"),
    ("windsurf", ".windsurf/extensions"),
)

_BROWSER_EXTENSION_ROOTS = (
    ("chrome", ".config/google-chrome/Default/Extensions"),
    ("chromium", ".config/chromium/Default/Extensions"),
    ("edge", ".config/microsoft-edge/Default/Extensions"),
    ("chrome", "Library/Application Support/Google/Chrome/Default/Extensions"),
    ("chromium", "Library/Application Support/Chromium/Default/Extensions"),
    ("edge", "Library/Application Support/Microsoft Edge/Default/Extensions"),
)

_IDE_AI_EXTENSIONS: dict[str, tuple[str, str, str | None]] = {
    "anthropic.claude-code": ("Claude Code", "anthropic", "claude_code"),
    "github.copilot": ("GitHub Copilot", "github", "copilot"),
    "github.copilot-chat": ("GitHub Copilot Chat", "github", "copilot"),
    "openai.chatgpt": ("OpenAI ChatGPT", "openai", None),
    "codeium.codeium": ("Codeium", "codeium", None),
    "continue.continue": ("Continue", "continue", None),
}

_BROWSER_AI_TERMS = (
    "artificial intelligence",
    "chatgpt",
    "claude",
    "copilot",
    "gemini",
    "perplexity",
    "large language model",
    "llm",
    "ai assistant",
    "ai coding",
)

_SECRET_SHAPE = re.compile(
    r"(?:"
    r"\bsk-[A-Za-z0-9_-]{8,}"
    r"|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{8,}"
    r"|\bAIza[0-9A-Za-z_-]{35}\b"
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|\b(?:token|secret|password|passwd|api[_-]?key|bearer)\b"
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r")",
    re.IGNORECASE,
)
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+ -]{0,79}$")
_IDE_EXTENSION_VERSION = re.compile(
    r"^(?P<id>.+)-(?P<version>\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)$"
)
_BROWSER_EXTENSION_ID = re.compile(r"^[a-p]{32}$")


def _safe_text(value: object, *, fallback: str = "unknown") -> str:
    if not isinstance(value, str):
        return fallback
    normalized = value.strip()
    if not normalized or not _SAFE_TEXT.fullmatch(normalized):
        return fallback
    if _SECRET_SHAPE.search(normalized):
        return fallback
    return normalized


def _safe_identifier(value: object) -> str:
    safe = _safe_text(value, fallback="redacted")
    return safe if safe != "unknown" else "redacted"


class _Scanner:
    def __init__(
        self,
        *,
        roots: ScanRoots,
        limits: ScanLimits,
        filesystem: FilesystemProbe,
        monotonic: Callable[[], float],
    ) -> None:
        self.roots = roots
        self.limits = limits
        self.filesystem = filesystem
        self.monotonic = monotonic
        self.started = monotonic()
        self.files_examined = 0
        self.items_emitted = 0
        self.errors: list[dict[str, str]] = []
        self._error_keys: set[tuple[str, str]] = set()
        self._time_exhausted = False
        self.evidence: dict[str, set[str]] = {
            product.id: set() for product in _PRODUCTS
        }
        self.versions: dict[str, set[str]] = {
            product.id: set() for product in _PRODUCTS
        }
        self.extensions: list[dict[str, object]] = []
        self.configurations: list[dict[str, object]] = []

        tagged_roots = [
            ("home", roots.home),
            *[("application", root) for root in roots.application_roots],
            *[("executable", root) for root in roots.executable_roots],
        ]
        if len(tagged_roots) > limits.max_roots:
            self._error("scanner", "root_limit_reached")
        allowed = tagged_roots[: limits.max_roots]
        self.home_enabled = any(kind == "home" for kind, _root in allowed)
        self.application_roots = tuple(
            root for kind, root in allowed if kind == "application"
        )
        self.executable_roots = tuple(
            root for kind, root in allowed if kind == "executable"
        )

    def collect(self) -> dict[str, object]:
        if self.home_enabled and self._within_time():
            self._scan_configurations()
        if self._within_time():
            self._scan_applications()
        if self._within_time():
            self._scan_executables()
        if self.home_enabled and self._within_time():
            self._scan_ide_extensions()
        if self.home_enabled and self._within_time():
            self._scan_browser_extensions()

        products = [self._product_record(product) for product in _PRODUCTS]
        self.extensions.sort(key=lambda item: (str(item["host"]), str(item["id"])))
        self.configurations.sort(
            key=lambda item: (str(item["product_id"]), str(item["source"]))
        )
        self.errors.sort(key=lambda item: (item["source"], item["code"]))
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "completed",
            "collection_mode": "one_shot_read_only",
            "network_used": False,
            "products": products,
            "extensions": self.extensions,
            "configurations": self.configurations,
            "errors": self.errors,
            "limits": {
                "max_roots": self.limits.max_roots,
                "max_files": self.limits.max_files,
                "max_file_bytes": self.limits.max_file_bytes,
                "max_items": self.limits.max_items,
                "max_directory_entries": self.limits.max_directory_entries,
                "max_seconds": self.limits.max_seconds,
            },
            "summary": {
                "products_present": sum(
                    product["presence"] == "present" for product in products
                ),
                "extensions": len(self.extensions),
                "configurations": len(self.configurations),
                "errors": len(self.errors),
            },
            "privacy": {
                "raw_file_contents_collected": False,
                "prompts_collected": False,
                "browser_history_collected": False,
                "cookies_collected": False,
                "secrets_or_tokens_collected": False,
                "account_identifiers_collected": False,
                "persistent_state_written": False,
            },
        }

    def _within_time(self) -> bool:
        if self._time_exhausted:
            return False
        if self.monotonic() - self.started > self.limits.max_seconds:
            self._time_exhausted = True
            self._error("scanner", "time_limit_reached")
            return False
        return True

    def _error(self, source: str, code: str) -> None:
        key = (source, code)
        if key not in self._error_keys:
            self._error_keys.add(key)
            self.errors.append({"source": source, "code": code})

    def _take_file(self, source: str) -> bool:
        if not self._within_time():
            return False
        if self.files_examined >= self.limits.max_files:
            self._error("scanner", "file_limit_reached")
            return False
        self.files_examined += 1
        return True

    def _emit(self, collection: list[dict[str, object]], item: dict[str, object]) -> None:
        if self.items_emitted >= self.limits.max_items:
            self._error("scanner", "item_limit_reached")
            return
        self.items_emitted += 1
        collection.append(item)

    def _stat(
        self,
        root: Path,
        relative: str | Path,
        *,
        source: str,
    ) -> os.stat_result | None:
        try:
            return self.filesystem.stat_relative(root, relative)
        except ProbeFailure as exc:
            if exc.code != "missing":
                self._error(source, exc.code)
        except OSError:
            self._error(source, "metadata_unreadable")
        return None

    def _entries(
        self,
        root: Path,
        relative: str | Path,
        *,
        source: str,
    ) -> tuple[ProbeEntry, ...]:
        try:
            entries = self.filesystem.list_directory(
                root,
                relative,
                self.limits.max_directory_entries,
            )
            if len(entries) > self.limits.max_directory_entries:
                self._error(source, "directory_entry_limit_reached")
                return entries[: self.limits.max_directory_entries]
            return entries
        except (OSError, ProbeFailure) as exc:
            code = exc.code if isinstance(exc, ProbeFailure) else "metadata_unreadable"
            if code != "missing":
                self._error(source, code)
            return ()

    def _read(
        self,
        root: Path,
        relative: str | Path,
        *,
        source: str,
    ) -> bytes | None:
        if not self._take_file(source):
            return None
        try:
            return self.filesystem.read_limited(
                root,
                relative,
                self.limits.max_file_bytes,
            )
        except ProbeFailure as exc:
            if exc.code != "missing":
                self._error(source, exc.code)
        except OSError:
            self._error(source, "metadata_unreadable")
        return None

    def _scan_configurations(self) -> None:
        for spec in _CONFIGS:
            if not self._within_time():
                return
            file_stat = self._stat(
                self.roots.home,
                spec.relative_path,
                source=spec.source,
            )
            if file_stat is None:
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                self._error(spec.source, "unsupported_file_type")
                continue
            product = spec.product_id
            if product in self.evidence:
                self.evidence[product].add("configuration")
            data = self._read(
                self.roots.home,
                spec.relative_path,
                source=spec.source,
            )
            if data is None:
                continue
            metadata = self._parse_config(data, spec)
            if metadata is None:
                continue
            self._emit(
                self.configurations,
                {
                    "product_id": product,
                    "kind": "mcp_agent_configuration",
                    "source": spec.source,
                    "status": "present",
                    "metadata": metadata,
                },
            )

    def _parse_config(
        self,
        data: bytes,
        spec: _ConfigSpec,
    ) -> dict[str, object] | None:
        try:
            if spec.format == "toml":
                document = tomllib.loads(data.decode("utf-8"))
            else:
                document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError):
            self._error(spec.source, "malformed_metadata")
            return None
        if not isinstance(document, dict):
            self._error(spec.source, "malformed_metadata")
            return None

        metadata: dict[str, object] = {}
        for key in ("model", "model_provider", "approval_policy", "sandbox_mode"):
            safe = _safe_text(document.get(key))
            if safe != "unknown":
                metadata[key] = safe
            elif key == "model" and key in document:
                metadata[key] = "unknown"

        mcp_servers = document.get("mcp_servers")
        if not isinstance(mcp_servers, dict):
            mcp_servers = document.get("mcpServers")
        if isinstance(mcp_servers, dict):
            if len(mcp_servers) > 32:
                self._error(spec.source, "mcp_server_limit_reached")
            entries = sorted(mcp_servers.items(), key=lambda entry: str(entry[0]))[:32]
            names = sorted({_safe_identifier(name) for name, _ in entries})
            metadata["mcp_server_names"] = names
            details = []
            for name, config in entries:
                if not isinstance(config, dict) or _safe_identifier(name) == "redacted":
                    continue
                item = {"name": _safe_identifier(name), "transport": "unknown"}
                url = config.get("url")
                if isinstance(url, str):
                    try:
                        parsed = urlsplit(url)
                        host = (parsed.hostname or "").lower().rstrip(".")
                        if parsed.scheme in {"https", "http"} and re.fullmatch(r"[a-z0-9.-]{1,128}", host) and not _SECRET_SHAPE.search(host):
                            item.update(transport="remote", destination_host=host)
                    except ValueError:
                        pass
                elif isinstance(config.get("command"), str):
                    item["transport"] = "stdio"
                    executable = config["command"].replace("\\", "/").rsplit("/", 1)[-1].lower()
                    if executable in {"npx", "node", "uvx", "uv", "python", "python3", "docker", "npx.cmd", "node.exe", "python.exe"}:
                        item["executable"] = executable
                details.append(item)
            if details:
                metadata["mcp_servers"] = details
        return metadata

    def _scan_applications(self) -> None:
        for product in _PRODUCTS:
            for application_root in self.application_roots:
                for application_name in product.application_names:
                    if not self._within_time():
                        return
                    source = f"{product.id}_application"
                    app_stat = self._stat(
                        application_root,
                        application_name,
                        source=source,
                    )
                    if app_stat is None:
                        continue
                    if not stat.S_ISDIR(app_stat.st_mode):
                        continue
                    self.evidence[product.id].add("application")
                    plist_relative = (
                        Path(application_name) / "Contents/Info.plist"
                    )
                    plist_stat = self._stat(
                        application_root,
                        plist_relative,
                        source=source,
                    )
                    if plist_stat is not None and stat.S_ISREG(plist_stat.st_mode):
                        self._read_application_version(
                            product.id,
                            application_root,
                            plist_relative,
                            source=source,
                        )

    def _read_application_version(
        self,
        product_id: str,
        root: Path,
        relative: str | Path,
        *,
        source: str,
    ) -> None:
        data = self._read(root, relative, source=source)
        if data is None:
            return
        try:
            document = plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError):
            self._error(source, "malformed_metadata")
            return
        if not isinstance(document, dict):
            self._error(source, "malformed_metadata")
            return
        version = _safe_text(
            document.get("CFBundleShortVersionString")
            or document.get("CFBundleVersion")
        )
        if version != "unknown":
            self.versions[product_id].add(version)

    def _scan_executables(self) -> None:
        for product in _PRODUCTS:
            for executable_root in self.executable_roots:
                for executable_name in product.executable_names:
                    if not self._within_time():
                        return
                    source = f"{product.id}_executable"
                    file_stat = self._stat(
                        executable_root,
                        executable_name,
                        source=source,
                    )
                    if file_stat is None:
                        continue
                    is_executable = bool(
                        file_stat.st_mode
                        & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    )
                    if stat.S_ISREG(file_stat.st_mode) and is_executable:
                        self.evidence[product.id].add("executable")

    def _scan_ide_extensions(self) -> None:
        for host, relative_root in _IDE_EXTENSION_ROOTS:
            source = f"{host}_extensions"
            for entry in self._entries(
                self.roots.home,
                relative_root,
                source=source,
            ):
                if not self._within_time():
                    return
                if entry.is_symlink:
                    self._error(source, "symlink_skipped")
                    continue
                if not entry.is_dir:
                    continue
                match = _IDE_EXTENSION_VERSION.fullmatch(entry.name)
                if match is None:
                    continue
                extension_id = match.group("id").lower()
                catalog = _IDE_AI_EXTENSIONS.get(extension_id)
                if catalog is None:
                    continue
                name, provider, product_id = catalog
                version = _safe_text(match.group("version"))
                self._emit(
                    self.extensions,
                    {
                        "id": extension_id,
                        "name": name,
                        "provider": provider,
                        "host": host,
                        "category": "ide",
                        "presence": "present",
                        "version": version,
                        "approval_status": "unknown",
                    },
                )
                if product_id:
                    self.evidence[product_id].add("ide_extension")
                    if version != "unknown":
                        self.versions[product_id].add(version)

    def _scan_browser_extensions(self) -> None:
        for host, relative_root in _BROWSER_EXTENSION_ROOTS:
            source = f"{host}_extensions"
            for extension_entry in self._entries(
                self.roots.home,
                relative_root,
                source=source,
            ):
                if not self._within_time():
                    return
                if extension_entry.is_symlink:
                    self._error(source, "symlink_skipped")
                    continue
                if (
                    not extension_entry.is_dir
                    or not _BROWSER_EXTENSION_ID.fullmatch(extension_entry.name)
                ):
                    continue
                version_root = Path(relative_root) / extension_entry.name
                for version_entry in self._entries(
                    self.roots.home,
                    version_root,
                    source=source,
                ):
                    if not self._within_time():
                        return
                    if version_entry.is_symlink:
                        self._error(source, "symlink_skipped")
                        continue
                    if not version_entry.is_dir:
                        continue
                    manifest_relative = (
                        version_root / version_entry.name / "manifest.json"
                    )
                    manifest_stat = self._stat(
                        self.roots.home,
                        manifest_relative,
                        source=source,
                    )
                    if (
                        manifest_stat is None
                        or not stat.S_ISREG(manifest_stat.st_mode)
                    ):
                        continue
                    data = self._read(
                        self.roots.home,
                        manifest_relative,
                        source=source,
                    )
                    if data is None:
                        continue
                    manifest = self._parse_browser_manifest(data, source=source)
                    if manifest is None:
                        continue
                    name, version, provider = manifest
                    self._emit(
                        self.extensions,
                        {
                            "id": extension_entry.name,
                            "name": name,
                            "provider": provider,
                            "host": host,
                            "category": "browser",
                            "presence": "present",
                            "version": version,
                            "approval_status": "unknown",
                        },
                    )

    def _parse_browser_manifest(
        self,
        data: bytes,
        *,
        source: str,
    ) -> tuple[str, str, str] | None:
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(source, "malformed_metadata")
            return None
        if not isinstance(document, dict):
            self._error(source, "malformed_metadata")
            return None
        raw_name = document.get("name")
        raw_description = document.get("description")
        classifier = " ".join(
            value.lower()
            for value in (raw_name, raw_description)
            if isinstance(value, str)
        )
        if not any(term in classifier for term in _BROWSER_AI_TERMS):
            return None
        name = _safe_text(raw_name)
        version = _safe_text(document.get("version"))
        provider = self._provider_from_text(classifier)
        return name, version, provider

    @staticmethod
    def _provider_from_text(value: str) -> str:
        providers = (
            ("claude", "anthropic"),
            ("chatgpt", "openai"),
            ("copilot", "github"),
            ("gemini", "google"),
            ("perplexity", "perplexity"),
        )
        return next(
            (provider for marker, provider in providers if marker in value),
            "unknown",
        )

    def _product_record(self, product: _ProductSpec) -> dict[str, object]:
        versions = self.versions[product.id]
        version = next(iter(versions)) if len(versions) == 1 else "unknown"
        return {
            "id": product.id,
            "name": product.name,
            "provider": product.provider,
            "category": product.category,
            "presence": "present" if self.evidence[product.id] else "unknown",
            "version": version,
            "evidence_types": sorted(self.evidence[product.id]),
            "approval_status": "unknown",
            "account": {
                "status": "unknown",
                "identifiers_collected": False,
            },
        }


def collect_endpoint_metadata(
    *,
    roots: ScanRoots | None = None,
    limits: ScanLimits | None = None,
    filesystem: FilesystemProbe | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Perform one bounded local metadata collection and return its JSON contract."""

    scanner = _Scanner(
        roots=roots or ScanRoots.defaults(),
        limits=limits or ScanLimits(),
        filesystem=filesystem or LocalFilesystemProbe(),
        monotonic=monotonic,
    )
    return scanner.collect()


def collect_platform_endpoint_metadata(
    *,
    platform: str | None = None,
    **kwargs: object,
) -> dict[str, object]:
    """Use the platform-specific, bounded metadata source when one exists."""

    if (platform or sys.platform).lower().startswith("win"):
        from .windows_metadata_scanner import collect_windows_endpoint_metadata

        return collect_windows_endpoint_metadata(**kwargs)
    return collect_endpoint_metadata(**kwargs)
